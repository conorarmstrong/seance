#![forbid(unsafe_code)]
//! iMessage / SMS Parser Module
//!
//! Parses iOS iMessage/SMS databases (sms.db, chat.db) extracting messages,
//! contacts, and attachments as forensic artifacts.
//!
//! ## Supported Databases
//!
//! - `sms.db` - iOS messages database (found in iOS backups)
//! - `chat.db` - macOS Messages database
//!
//! ## Schema
//!
//! Core tables: `message`, `handle`, `chat`, `attachment`
//! Join tables: `chat_message_join`, `chat_handle_join`, `message_attachment_join`
//!
//! ## Timestamps
//!
//! Uses Cocoa/Core Data epoch (seconds since 2001-01-01 00:00:00 UTC).
//! Modern iOS (14+) stores nanoseconds; legacy stores seconds. We detect
//! the format by checking if the value exceeds 1 billion.
//!
//! ## Schema drift
//!
//! Apple's own `_SqliteDatabaseProperties._ClientVersion` row is checked
//! against the window observed on real stores (`SUPPORTED_CLIENT_VERSION`);
//! `PRAGMA user_version` is 0 on every real store seen and is not the signal.
//! Every column is resolved through a field map. A store outside the window,
//! one that records no client version, or one whose columns no candidate name
//! matches, still parses and carries a `ParserStaleWarning` record saying
//! which — never a silent shortfall.

#[cfg(test)]
mod schema_golden_tests;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use seance_core::io::IncompleteReason;
use seance_core::time::cocoa_to_unix_nanos;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::adopt::inline_marker::{field_drift_marker, version_marker};
use seance_sqlite_util::{
    cap_marker, probe_columns, CapCounter, FieldMap, Presence, RowDrops, SchemaProbe,
    SupportedRange,
};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Maximum number of messages to extract per database.
const MAX_MESSAGE_ENTRIES: usize = 500_000;

/// The parser identity a schema warning is filed under.
const SCHEMA_APP: &str = "imessage";

/// The `_SqliteDatabaseProperties._ClientVersion` window this parser was
/// validated against, on real stores only — never widened by guesswork.
/// Observed: 9005 in plaso's `test_data/imessage_chat.db`, 14005 in the
/// Magnet 2021 macOS CTF `chat.db`, 15009 in the Magnet 2022 CTF iPhone 8
/// `sms.db`. `PRAGMA user_version` is 0 on all three, so it is not the
/// signal here. A store outside the window still parses; it also carries a
/// `ParserStaleWarning`.
const SUPPORTED_CLIENT_VERSION: SupportedRange = SupportedRange {
    min: 9005,
    max: Some(15009),
};

/// The real stores each endpoint of [`SUPPORTED_CLIENT_VERSION`] was read out
/// of, written on every schema record as `validated_against`.
const CLIENT_VERSION_EVIDENCE: &str = "plaso test_data/imessage_chat.db (_ClientVersion 9005); \
     Magnet 2021 macOS CTF chat.db (14005); Magnet 2022 CTF iPhone 8 sms.db (15009)";

/// The logical fields each table is read through, with the physical column
/// names that carried them in the real stores above. A rename in a newer
/// Messages client is then one more candidate here, not a code path — and
/// until it is added, the field is reported as unresolved rather than read as
/// empty. The version-dependent optional columns (`attributedBody`,
/// `associated_message_guid`, `reply_to_guid`) stay on [`SchemaProbe`]: their
/// absence on an older store is a finding, not drift.
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("rowid", &["ROWID"]),
    ("guid", &["guid"]),
    ("text", &["text"]),
    ("date", &["date"]),
    ("date_read", &["date_read"]),
    ("date_delivered", &["date_delivered"]),
    ("is_from_me", &["is_from_me"]),
    ("is_read", &["is_read"]),
    ("service", &["service"]),
    ("cache_has_attachments", &["cache_has_attachments"]),
    ("handle_id", &["handle_id"]),
];
const HANDLE_FIELDS: &[(&str, &[&str])] = &[("rowid", &["ROWID"]), ("id", &["id"])];
const CHAT_FIELDS: &[(&str, &[&str])] = &[
    ("rowid", &["ROWID"]),
    ("chat_identifier", &["chat_identifier"]),
    ("display_name", &["display_name"]),
];
const CHAT_MESSAGE_JOIN_FIELDS: &[(&str, &[&str])] =
    &[("chat_id", &["chat_id"]), ("message_id", &["message_id"])];
const ATTACHMENT_FIELDS: &[(&str, &[&str])] = &[
    ("rowid", &["ROWID"]),
    ("guid", &["guid"]),
    ("filename", &["filename"]),
    ("mime_type", &["mime_type"]),
    ("total_bytes", &["total_bytes"]),
    ("created_date", &["created_date"]),
    ("transfer_name", &["transfer_name"]),
    ("uti", &["uti"]),
    ("is_outgoing", &["is_outgoing"]),
];
const MESSAGE_ATTACHMENT_JOIN_FIELDS: &[(&str, &[&str])] = &[
    ("message_id", &["message_id"]),
    ("attachment_id", &["attachment_id"]),
];

/// One table's logical-to-physical column map, resolved against the store.
struct Fields {
    table: &'static str,
    map: FieldMap,
}

impl Fields {
    /// Resolve `specs` against the columns actually present. `Err` when the
    /// column list itself would not read: that is "could not look", and the
    /// caller must not spend it as "the columns are gone".
    fn resolve(conn: &Connection, table: &'static str, specs: &[(&str, &[&str])]) -> Result<Self> {
        let present = probe_columns(conn, table)
            .map_err(|why| anyhow::anyhow!("the `{table}` columns could not be read: {why}"))?;
        Ok(Self {
            table,
            map: FieldMap::resolve(&present, specs),
        })
    }

    /// `alias.column AS logical`, or `NULL AS logical` when no candidate
    /// resolved — the SELECT-list form.
    fn select(&self, alias: &str, logical: &str) -> String {
        match self.map.column(logical) {
            Some(col) => format!("{alias}.{col} AS {logical}"),
            None => format!("NULL AS {logical}"),
        }
    }

    /// `alias.column`, or `fallback` — the form for a join condition or an
    /// ORDER BY, where an alias is not allowed. The row id falls back to
    /// SQLite's own `rowid`, which still identifies the row when the declared
    /// column has gone.
    fn expr_or(&self, alias: &str, logical: &str, fallback: &str) -> String {
        match self.map.column(logical) {
            Some(col) => format!("{alias}.{col}"),
            None => fallback.to_string(),
        }
    }

    /// The marker naming every logical field no candidate column matched, or
    /// `None` when all resolved. `recovered` is how many records the walk still
    /// produced without those fields.
    fn drift_marker(&self, case_id: Uuid, parent_id: Uuid, recovered: usize) -> Option<Artifact> {
        field_drift_marker(
            case_id, parent_id, SCHEMA_APP, self.table, &self.map, recovered,
        )
    }
}

/// Apple's own version row: `_SqliteDatabaseProperties` key `_ClientVersion`.
/// `Ok(None)` when the store does not record one; `Err` when it could not be
/// read — and the caller must not spend either as "in range".
fn client_version(conn: &Connection) -> std::result::Result<Option<i64>, String> {
    match seance_sqlite_util::probe_table(conn, "_SqliteDatabaseProperties") {
        Presence::Present => {}
        Presence::Absent => return Ok(None),
        Presence::Undetermined(why) => return Err(why),
    }
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM _SqliteDatabaseProperties WHERE key = '_ClientVersion'",
            [],
            |r| seance_sqlite_util::row_text(r, 0).ok_or(rusqlite::Error::InvalidQuery),
        )
        .optional()
        .map_err(|e| format!("`_SqliteDatabaseProperties` would not read: {e}"))?;
    match value {
        None => Ok(None),
        Some(v) => v
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|_| format!("`_ClientVersion` is `{v}`, not a number")),
    }
}

/// Compare the store's `_ClientVersion` with the validated window and return
/// the marker to file, if any. HUNT-204: every record here states the window,
/// so each names the real stores its endpoints were read out of.
fn schema_version_marker(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Option<Artifact> {
    version_marker(
        client_version(conn),
        "the store has no `_SqliteDatabaseProperties` `_ClientVersion` row, which is where \
         every validated store carried it",
        case_id,
        parent_id,
        SCHEMA_APP,
        &SUPPORTED_CLIENT_VERSION,
        CLIENT_VERSION_EVIDENCE,
    )
}

pub struct IMessageParser;

/// Fast filename pre-filter for iMessage/SMS databases. Permissive on purpose:
/// this only decides whether to open the file — the authoritative check is the
/// `message`/`handle`/`chat` schema (`has_imessage_schema`) run after opening,
/// which rejects any false positive. Matching on suffix/substring rather than an
/// exact name means renamed or path-prefixed copies (e.g. `imessage_chat.db`,
/// `Messages/chat.db`, an iOS-backup hash) are still parsed.
fn identify_imessage_db(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("chat.db")
        || n.ends_with("sms.db")
        || n.ends_with("chat.db-wal")
        || n.contains("imessage")
        || n.contains("mobilesms")
}

/// Maximum on-disk database size we will spill and open.
const MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Full-precision Unix epoch nanoseconds for a decoded Cocoa timestamp.
/// None when the sub-second part is zero or the value does not fit in i64.
fn unix_ns(secs: i64, nanos: u32) -> Option<i64> {
    if nanos == 0 {
        return None;
    }
    secs.checked_mul(1_000_000_000)?.checked_add(nanos as i64)
}

/// True if the staged copy begins with the SQLite file magic.
///
/// Used to tell "not our database" from "a chat.db that would not open": the
/// first must stay silent, the second must be reported.
fn staged_looks_like_sqlite(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && seance_core::io::is_sqlite_header(&head)
}

/// Probe for an optional table, returning `(present, why-we-could-not-tell)`.
///
/// Never collapses a catalogue read failure into "absent": the caller uses these
/// flags to decide which SELECT it runs, and a `false` produced by a failure
/// silently removes a JOIN — after which the missing correspondent or the
/// missing attachment reads as evidence rather than as a gap in the extraction.
fn probe_table(conn: &Connection, table: &str) -> (bool, Option<String>) {
    match conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    ) {
        Ok(present) => (present, None),
        Err(e) => (false, Some(format!("could not look for '{table}': {e}"))),
    }
}

/// Verify the database has the expected iMessage schema.
///
/// Returns `Err` when the catalogue itself could not be read. A corrupt chat.db
/// answers that query with an error, and reporting it as "table absent" made an
/// unreadable message store render as a device with no messages: "no such
/// table" and "could not tell" must never look the same to an examiner.
fn has_imessage_schema(conn: &Connection) -> Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='message'",
        [],
        |row| row.get(0),
    )
    .context("Failed to read the schema catalogue looking for the 'message' table")
}

/// The SQL expressions for `message`'s optional columns, plus the probe that
/// produced them.
///
/// These columns arrived in different iOS versions, so each is probed
/// independently: `associated_message_guid` (tapbacks/edits) exists from iOS 10,
/// `reply_to_guid` (threaded replies) only from iOS 14. Gating both on one flag
/// makes the query name a column the schema lacks, `prepare()` fails, and every
/// message is dropped.
///
/// The probes go through [`SchemaProbe`], not `.unwrap_or(false)`. The table
/// probes in the caller already keep "absent" apart from "could not tell"; these
/// did not, so a catalogue read that failed here substituted
/// `NULL AS attributedBody` — and modern iOS stores most message bodies ONLY in
/// `attributedBody`. The conversation then came out empty or attachment-only,
/// with nothing saying the store was unreadable for columns rather than short of
/// text (B8-012).
///
/// The returned probe is the caller's obligation: stamp `probe.detail()` on the
/// records and append `probe.marker(..)`.
fn optional_message_columns(
    conn: &Connection,
) -> (&'static str, &'static str, &'static str, SchemaProbe) {
    let mut probe = SchemaProbe::new();
    let assoc = if probe.has_column(conn, "message", "associated_message_guid") {
        "m.associated_message_guid"
    } else {
        "NULL AS associated_message_guid"
    };
    let reply = if probe.has_column(conn, "message", "reply_to_guid") {
        "m.reply_to_guid"
    } else {
        "NULL AS reply_to_guid"
    };
    // Modern iMessage (iOS 13+) increasingly leaves `text` NULL and stores the
    // body only in `attributedBody`, an Apple typedstream blob. Probe for it so
    // we can decode the message text when `text` is empty.
    let body = if probe.has_column(conn, "message", "attributedBody") {
        "m.attributedBody"
    } else {
        "NULL AS attributedBody"
    };
    (assoc, reply, body, probe)
}

/// Parse messages by joining message, handle, and chat tables.
fn parse_messages(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Result<Vec<Artifact>> {
    parse_messages_capped(conn, case_id, parent_id, MAX_MESSAGE_ENTRIES)
}

/// [`parse_messages`] with the row budget supplied, so the cap-reached path is
/// reachable in a test without seeding half a million messages.
fn parse_messages_capped(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();

    // Optional-table probes. A probe that ERRORS is not "the table is absent":
    // answering `false` for the attachment tables makes every message in the
    // conversation read as having carried no media, and answering it for
    // `handle`/`chat_message_join` drops the correspondent's identity — both
    // drawn from a failure rather than from the device. The note is carried out
    // to the records below.
    let (has_handle, e_handle) = probe_table(conn, "handle");
    let (has_chat_join, e_chat) = probe_table(conn, "chat_message_join");
    let (has_chat, e_chat_table) = probe_table(conn, "chat");
    let (has_attachment_join, e_ajoin) = probe_table(conn, "message_attachment_join");
    let (has_attachment, e_att) = probe_table(conn, "attachment");
    let schema_probe_error = e_handle.or(e_chat).or(e_chat_table).or(e_ajoin).or(e_att);

    // Schema-drift defence: the client version against the validated window,
    // then each table's columns against the names the parser knows. Findings,
    // filed beside the records; never a reason to stop the walk.
    let mut schema_markers = Vec::new();
    schema_markers.extend(schema_version_marker(conn, case_id, parent_id));
    let msg = Fields::resolve(conn, "message", MESSAGE_FIELDS)?;
    let handle = if has_handle {
        Some(Fields::resolve(conn, "handle", HANDLE_FIELDS)?)
    } else {
        None
    };
    let chat = if has_chat_join && has_chat {
        Some((
            Fields::resolve(conn, "chat", CHAT_FIELDS)?,
            Fields::resolve(conn, "chat_message_join", CHAT_MESSAGE_JOIN_FIELDS)?,
        ))
    } else {
        None
    };

    let (assoc_col, reply_col, body_col, col_probe) = optional_message_columns(conn);
    // Kept for the per-record stamp below: every message built from a query
    // whose optional columns could not be probed is a message whose text,
    // tapback or reply link may have been dropped by the probe rather than
    // absent from the device.
    let column_probe_error = col_probe.detail();

    // Build the query based on available tables.
    //
    // `chat_message_join` is many-to-many: one message can belong to several
    // chats (merged/split conversations, an SMS row also filed under iMessage).
    // Joining it directly fans the message out into one artifact per chat —
    // duplicate messages, inflated counts, and a LIMIT that counts join rows
    // rather than messages. Resolve the chat with a scalar subquery instead, so
    // each message yields exactly one row; the lowest chat id keeps the choice
    // deterministic across runs.
    //
    // Every column comes through the field map: a renamed one becomes `NULL AS
    // <field>` here and a named entry on the drift marker, instead of a failed
    // `prepare()` that dropped every message.
    let m_rowid = msg.expr_or("m", "rowid", "m.rowid");
    let message_columns = format!(
        "{} AS rowid, {}, {}, {}, {}, {}, {}, {}, {}, {}",
        m_rowid,
        msg.select("m", "guid"),
        msg.select("m", "text"),
        msg.select("m", "date"),
        msg.select("m", "date_read"),
        msg.select("m", "date_delivered"),
        msg.select("m", "is_from_me"),
        msg.select("m", "is_read"),
        msg.select("m", "service"),
        msg.select("m", "cache_has_attachments"),
    );
    let order_date = msg.expr_or("m", "date", "NULL");
    let handle_join = handle.as_ref().map(|h| {
        (
            format!(
                "LEFT JOIN handle h ON {} = {}",
                msg.expr_or("m", "handle_id", "NULL"),
                h.expr_or("h", "rowid", "h.rowid")
            ),
            match h.map.column("id") {
                Some(col) => format!("h.{col} AS handle_id_str"),
                None => "NULL AS handle_id_str".to_string(),
            },
        )
    });
    let query = match (&handle_join, &chat) {
        (Some((handle_join, handle_col)), Some((c, cmj))) => format!(
            "SELECT {message_columns},
                    {assoc_col}, {reply_col},
                    {handle_col},
                    {chat_identifier}, {display_name}, {body_col}
             FROM message m
             {handle_join}
             LEFT JOIN chat c ON {c_rowid} = (
                 SELECT {cmj_chat} FROM chat_message_join cmj
                 WHERE {cmj_message} = {m_rowid}
                 ORDER BY {cmj_chat} LIMIT 1
             )
             ORDER BY {order_date} DESC
             LIMIT ?1",
            chat_identifier = c.select("c", "chat_identifier"),
            display_name = c.select("c", "display_name"),
            c_rowid = c.expr_or("c", "rowid", "c.rowid"),
            cmj_chat = cmj.expr_or("cmj", "chat_id", "NULL"),
            cmj_message = cmj.expr_or("cmj", "message_id", "NULL"),
        ),
        (Some((handle_join, handle_col)), None) => format!(
            "SELECT {message_columns},
                    {assoc_col}, {reply_col},
                    {handle_col},
                    NULL AS chat_identifier, NULL AS display_name, {body_col}
             FROM message m
             {handle_join}
             ORDER BY {order_date} DESC
             LIMIT ?1"
        ),
        (None, _) => format!(
            "SELECT {message_columns},
                NULL AS associated_message_guid, NULL AS reply_to_guid,
                NULL AS handle_id_str,
                NULL AS chat_identifier, NULL AS display_name, {body_col}
         FROM message m
         ORDER BY {order_date} DESC
         LIMIT ?1"
        ),
    };
    let query = query.as_str();

    // Inventory the attachments first. A failure here must be visible on the
    // messages that claim to carry one: swallowing it leaves a conversation
    // whose messages say `has_attachments` while no attachment record exists,
    // which reads as "the media was never there".
    let mut attachment_artifacts = Vec::new();
    // Seeded from the table probes: a probe that failed is exactly the case
    // where the inventory below never runs, so without this the messages would
    // present as clean rather than as unexamined for media.
    let mut attachment_error: Option<String> = schema_probe_error;
    let mut attachment_cap: Option<CapCounter> = None;
    let mut attachment_drops = RowDrops::new();
    if has_attachment && has_attachment_join {
        match parse_attachments(conn, case_id, parent_id, max_entries) {
            Ok((a, cap, dropped, drift)) => {
                attachment_artifacts = a;
                if cap.truncated() {
                    attachment_cap = Some(cap);
                }
                attachment_drops = dropped;
                // An attachment table missing a column the parser knows is an
                // inventory this tool could not take in full: the messages
                // that claim media keep their per-message stamp, and the
                // drift marker names the fields.
                if !drift.is_empty() {
                    attachment_error = Some(
                        drift
                            .iter()
                            .filter_map(|m| m.metadata["detail"].as_str())
                            .collect::<Vec<_>>()
                            .join("; "),
                    );
                }
                schema_markers.extend(drift);
            }
            Err(e) => {
                warn!("Failed to inventory iMessage attachments: {}", e);
                attachment_error = Some(e.to_string());
            }
        }
    }

    let mut stmt = conn
        .prepare(query)
        .context("Failed to prepare iMessage query")?;

    // One row past the cap is fetched purely so the walk can tell "this database
    // held exactly MAX_MESSAGE_ENTRIES messages" from "we stopped reading".
    let mut message_cap = CapCounter::new(max_entries);

    // Rows the query returned but `rusqlite` could not decode into the tuple
    // below (unexpected column type on a partially recovered page, a NULL where
    // the schema promised none). Counted, because `continue` alone makes them
    // vanish and the message count then reads as exact (B3-023).
    let mut drops = RowDrops::new();

    let rows = stmt
        .query_map([message_cap.limit()], |row| {
            Ok((
                row.get::<_, i64>(0)?,            // ROWID
                row.get::<_, Option<String>>(1)?, // guid
                row.get::<_, Option<String>>(2)?, // text
                row.get::<_, Option<i64>>(3)?,    // date
                row.get::<_, Option<i64>>(4)?,    // date_read
                row.get::<_, Option<i64>>(5)?,    // date_delivered
                // Optional: a corrupt or partially recovered row can leave these
                // NULL. A non-optional get would error and drop the whole
                // message; an unknown direction is recorded as unknown instead.
                row.get::<_, Option<i64>>(6)?,      // is_from_me
                row.get::<_, Option<i64>>(7)?,      // is_read
                row.get::<_, Option<String>>(8)?,   // service
                row.get::<_, Option<i64>>(9)?,      // cache_has_attachments
                row.get::<_, Option<String>>(10)?,  // associated_message_guid
                row.get::<_, Option<String>>(11)?,  // reply_to_guid
                row.get::<_, Option<String>>(12)?,  // handle_id_str (phone/email)
                row.get::<_, Option<String>>(13)?,  // chat_identifier
                row.get::<_, Option<String>>(14)?,  // display_name
                row.get::<_, Option<Vec<u8>>>(15)?, // attributedBody typedstream
            ))
        })
        .context("Failed to query iMessage messages")?;

    for row in rows {
        if !message_cap.admit() {
            break;
        }
        let (
            rowid,
            guid,
            text,
            date,
            date_read,
            date_delivered,
            is_from_me,
            is_read,
            service,
            has_attachments,
            associated_msg_guid,
            reply_to_guid,
            handle_id_str,
            chat_identifier,
            display_name,
            attributed_body,
        ) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skipping malformed iMessage row: {}", e);
                drops.record(&e);
                continue;
            }
        };

        // Modern iMessage often leaves `text` NULL and keeps the body in the
        // `attributedBody` typedstream blob; decode it so those messages are not
        // shown as empty/attachment-only.
        let text = match text {
            Some(t) if !t.is_empty() => Some(t),
            _ => attributed_body
                .as_deref()
                .and_then(seance_core::typedstream::extract_message_text),
        };

        // None (unset/zero) stays absent instead of becoming an epoch date
        let date_parts = date.and_then(cocoa_to_unix_nanos);
        let date_read_parts = date_read.and_then(cocoa_to_unix_nanos);
        let date_delivered_parts = date_delivered.and_then(cocoa_to_unix_nanos);

        // A NULL `is_from_me` means the direction was never recorded (corrupt or
        // partially recovered row): report it as unknown rather than guessing
        // "received" — the viewer already renders a null direction as unknown.
        let is_from_me = is_from_me.map(|v| v != 0);
        let is_read = is_read.map(|v| v != 0);
        let direction = is_from_me.map(|m| if m { "sent" } else { "received" });
        let contact = handle_id_str.as_deref().unwrap_or("Unknown");
        let text_preview = text
            .as_deref()
            .unwrap_or("")
            .chars()
            .take(80)
            .collect::<String>();

        let name = format!(
            "{}: {} — {}",
            direction.unwrap_or("message"),
            contact,
            if text_preview.is_empty() {
                "(attachment)"
            } else {
                &text_preview
            },
        );

        // A NULL `cache_has_attachments` never recorded whether the message
        // carried media; `false` would state that it carried none. Kept as an
        // Option so it serialises to null, the way `is_from_me` does.
        let has_attachments = has_attachments.map(|v| v != 0);

        let mut metadata = json!({
            "type": "iMessage",
            "subtype": "chat_message",
            "source_table": "message",
            "rowid": rowid,
            "guid": guid,
            "text": text,
            "date": date_parts.map(|(s, _)| s),
            "date_read": date_read_parts.map(|(s, _)| s),
            "date_delivered": date_delivered_parts.map(|(s, _)| s),
            "is_from_me": is_from_me,
            "is_read": is_read,
            "service": service,
            "direction": direction,
            "contact": handle_id_str,
            "chat_identifier": chat_identifier,
            "chat_display_name": display_name,
            "has_attachments": has_attachments,
            "associated_message_guid": associated_msg_guid,
            "reply_to_guid": reply_to_guid,
            "name": name,
        });

        // Preserve full nanosecond precision alongside the whole seconds
        if let Some(ns) = date_parts.and_then(|(s, n)| unix_ns(s, n)) {
            metadata["date_ns"] = json!(ns);
        }
        if let Some(ns) = date_read_parts.and_then(|(s, n)| unix_ns(s, n)) {
            metadata["date_read_ns"] = json!(ns);
        }
        if let Some(ns) = date_delivered_parts.and_then(|(s, n)| unix_ns(s, n)) {
            metadata["date_delivered_ns"] = json!(ns);
        }

        // This message says it carries media the inventory could not read, or
        // never recorded whether it did: mark it either way, so "no attachment
        // record" is never read as "no attachment". `unwrap_or(true)` is the
        // fail-closed side — an unknown flag with a broken inventory is exactly
        // the case that must not present as a clean message.
        if let Some(err) = attachment_error
            .as_ref()
            .filter(|_| has_attachments.unwrap_or(true))
        {
            metadata["attachment_inventory_incomplete"] = json!(true);
            metadata["incomplete_reason"] = json!(IncompleteReason::UnresolvedStructure.as_str());
            metadata["attachment_inventory_error"] = json!(err);
            // `attachment_inventory_incomplete` / `incomplete_reason` are local
            // to this parser; the API, export and cross-plugin honesty paths key
            // on `content_incomplete` / `content_incomplete_reason`. Without the
            // standard pair, a message whose media could not be inventoried
            // exported as a complete message that simply had no attachment
            // (B3-022). The bespoke keys stay for any existing consumer.
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] =
                json!(IncompleteReason::UnresolvedStructure.as_str());
        }

        // The optional-column probes could not be answered, so this message was
        // built from a query with `NULL` substituted for columns that may well
        // exist. On modern iOS the body lives only in `attributedBody`, so the
        // visible consequence is a message that reads as having had no text —
        // a fact about the extraction presented as a fact about the device
        // (B8-012).
        if let Some(err) = column_probe_error.as_ref() {
            metadata["schema_probe_incomplete"] = json!(true);
            metadata["schema_probe_error"] = json!(err);
            metadata["content_incomplete"] = json!(true);
            metadata["content_incomplete_reason"] =
                json!(IncompleteReason::UnresolvedStructure.as_str());
        }

        let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(parent_id)
            .with_subtype("chat_message");

        artifacts.push(artifact);
    }

    // The message walk is newest-first, so a cap drops the OLDEST messages —
    // the start of a conversation, which is usually the part an examiner is
    // asked about. Recording it only in a log would leave the artifact set
    // saying "this is the conversation".
    if message_cap.truncated() {
        artifacts.push(cap_marker(
            case_id,
            parent_id,
            "iMessageIncomplete",
            "message",
            &message_cap,
        ));
    }

    // Messages the walk fetched and could not decode. Without this the count
    // above is presented as the whole conversation (B3-023).
    {
        // `recovered` counts only the chat_message records, and is taken before
        // the marker is appended so the marker never counts itself.
        let recovered = artifacts
            .iter()
            .filter(|a| a.metadata["subtype"] == json!("chat_message"))
            .count();
        artifacts.extend(drops.marker(
            case_id,
            parent_id,
            "iMessageIncomplete",
            "message",
            recovered,
        ));
        // Optional-column probes that could not be answered. Stamped on each
        // message above, and declared once here so an examiner reading the
        // artifact set — not an individual message — still meets the fact.
        artifacts.extend(col_probe.marker(
            case_id,
            parent_id,
            "iMessageIncomplete",
            "message",
            recovered,
        ));
        schema_markers.extend(msg.drift_marker(case_id, parent_id, recovered));
        if let Some(h) = &handle {
            schema_markers.extend(h.drift_marker(case_id, parent_id, recovered));
        }
        if let Some((c, cmj)) = &chat {
            schema_markers.extend(c.drift_marker(case_id, parent_id, recovered));
            schema_markers.extend(cmj.drift_marker(case_id, parent_id, recovered));
        }
    }
    artifacts.extend(schema_markers);

    artifacts.extend(attachment_artifacts);

    {
        let recovered = artifacts
            .iter()
            .filter(|a| a.metadata["type"] == json!("iMessageAttachment"))
            .count();
        artifacts.extend(attachment_drops.marker(
            case_id,
            parent_id,
            "iMessageAttachmentIncomplete",
            "attachment",
            recovered,
        ));
    }

    // Same for the attachment inventory: stopping at the cap must not read as
    // "the older media was never attached".
    if let Some(cap) = attachment_cap {
        artifacts.push(cap_marker(
            case_id,
            parent_id,
            "iMessageAttachmentIncomplete",
            "attachment",
            &cap,
        ));
    }

    // The attachment table exists but could not be read: surface that as its own
    // record rather than returning a silently empty attachment list.
    if let Some(err) = attachment_error {
        let metadata = json!({
            // NOT `"iMessage"`. `conversation_summaries` selects ParsedRecords
            // by `metadata.$.type` with no subtype filter, and its iMessage
            // thread key COALESCEs down to the literal `'unknown'` — so a
            // status record filed under the message type is counted as a
            // message in an `unknown` conversation the custodian never had.
            // Same rule the `cap_marker` docs state; this hand-rolled record
            // was outside the sweep that fixed the helper call sites.
            "type": "iMessageIncomplete",
            "subtype": "parse_incomplete",
            "source_table": "attachment",
            "status": "AttachmentInventoryFailed",
            "attachment_inventory_incomplete": true,
            "incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            // The standard pair, so an unreadable attachment table is visible to
            // the API and export honesty paths and not only to this plugin's own
            // keys (B3-022).
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "error": err,
            "name": "iMessage attachments could not be inventoried",
        });
        artifacts.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(parent_id)
                .with_subtype("parse_incomplete"),
        );
    }

    Ok(artifacts)
}

/// Parse attachment records from the attachment table.
///
/// Returns the artifacts, the row budget that produced them, and the count of
/// rows that could not be decoded: the caller needs [`CapCounter::truncated`] to
/// know whether "no attachment record for this message" is a fact about the
/// device or an artefact of the cap, and the dropped count for the same reason
/// applied to corrupt rows (B3-023).
///
/// The fourth element is the schema-drift markers for the two attachment
/// tables, when a column the parser knows did not resolve.
fn parse_attachments(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<(Vec<Artifact>, CapCounter, RowDrops, Vec<Artifact>)> {
    let mut artifacts = Vec::new();
    let mut cap = CapCounter::new(max_entries);
    let mut drops = RowDrops::new();

    let att = Fields::resolve(conn, "attachment", ATTACHMENT_FIELDS)?;
    let maj = Fields::resolve(
        conn,
        "message_attachment_join",
        MESSAGE_ATTACHMENT_JOIN_FIELDS,
    )?;
    let msg = Fields::resolve(conn, "message", MESSAGE_FIELDS)?;

    // `message_attachment_join` carries the per-message link, so an attachment
    // can be shown against the message that actually sent or received it rather
    // than only against the conversation. The join is LEFT so an orphaned
    // attachment (present in the table but referenced by no surviving message)
    // is still reported, with no message id.
    let maj_message = maj.expr_or("maj", "message_id", "NULL");
    let select = format!(
        "SELECT {a_rowid} AS rowid, {guid}, {filename}, {mime_type}, {total_bytes},
                {created_date}, {transfer_name}, {uti}, {is_outgoing},
                {maj_message} AS message_id, {m_guid}
         FROM attachment a
         LEFT JOIN message_attachment_join maj ON {maj_attachment} = {a_rowid}
         LEFT JOIN message m ON {m_rowid} = {maj_message}
         ORDER BY {order_date} DESC
         LIMIT ?1",
        a_rowid = att.expr_or("a", "rowid", "a.rowid"),
        guid = att.select("a", "guid"),
        filename = att.select("a", "filename"),
        mime_type = att.select("a", "mime_type"),
        total_bytes = att.select("a", "total_bytes"),
        created_date = att.select("a", "created_date"),
        transfer_name = att.select("a", "transfer_name"),
        uti = att.select("a", "uti"),
        is_outgoing = att.select("a", "is_outgoing"),
        m_guid = msg.select("m", "guid"),
        maj_attachment = maj.expr_or("maj", "attachment_id", "NULL"),
        m_rowid = msg.expr_or("m", "rowid", "m.rowid"),
        order_date = att.expr_or("a", "created_date", "NULL"),
    );
    let mut stmt = conn
        .prepare(&select)
        .context("Failed to prepare attachment query")?;

    let rows = stmt
        .query_map([cap.limit()], |row| {
            Ok((
                row.get::<_, i64>(0)?,             // ROWID
                row.get::<_, Option<String>>(1)?,  // guid
                row.get::<_, Option<String>>(2)?,  // filename
                row.get::<_, Option<String>>(3)?,  // mime_type
                row.get::<_, Option<i64>>(4)?,     // total_bytes
                row.get::<_, Option<i64>>(5)?,     // created_date
                row.get::<_, Option<String>>(6)?,  // transfer_name
                row.get::<_, Option<String>>(7)?,  // uti
                row.get::<_, Option<i64>>(8)?,     // is_outgoing
                row.get::<_, Option<i64>>(9)?,     // message_id (message.ROWID)
                row.get::<_, Option<String>>(10)?, // message guid
            ))
        })
        .context("Failed to query attachments")?;

    for row in rows {
        if !cap.admit() {
            break;
        }
        let (
            rowid,
            guid,
            filename,
            mime_type,
            total_bytes,
            created_date,
            transfer_name,
            uti,
            is_outgoing,
            message_rowid,
            message_guid,
        ) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skipping malformed attachment row: {}", e);
                drops.record(&e);
                continue;
            }
        };

        // None (unset/zero) stays absent instead of becoming an epoch date
        let created_parts = created_date.and_then(cocoa_to_unix_nanos);
        let display_name = transfer_name
            .as_deref()
            .or(filename.as_deref())
            .unwrap_or("unknown");

        let mut metadata = json!({
            "type": "iMessageAttachment",
            "subtype": "chat_attachment",
            "source_table": "attachment",
            "rowid": rowid,
            "guid": guid,
            "filename": filename,
            "mime_type": mime_type,
            "total_bytes": total_bytes,
            "created_date": created_parts.map(|(s, _)| s),
            "transfer_name": transfer_name,
            "uti": uti,
            "is_outgoing": is_outgoing.map(|v| v != 0),
            // Per-message link from message_attachment_join, so the UI can show
            // the attachment inline against its own message.
            "message_rowid": message_rowid,
            "message_guid": message_guid,
            "name": format!("Attachment: {}", display_name),
        });

        if let Some(ns) = created_parts.and_then(|(s, n)| unix_ns(s, n)) {
            metadata["created_date_ns"] = json!(ns);
        }

        let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(parent_id)
            .with_subtype("chat_attachment");

        artifacts.push(artifact);
    }

    let recovered = artifacts.len();
    let drift = att
        .drift_marker(case_id, parent_id, recovered)
        .into_iter()
        .chain(maj.drift_marker(case_id, parent_id, recovered))
        .collect();
    Ok((artifacts, cap, drops, drift))
}

impl ForensicsModule for IMessageParser {
    fn id(&self) -> &str {
        "plugin.apple.imessage"
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

        if !identify_imessage_db(name) {
            return Ok(Vec::new());
        }

        info!("IMessageParser processing: {}", name);

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
                "type": "iMessage",
                "file_name": name,
                "status": "Identified",
                "name": format!("iMessage Database (not parsed - no data): {}", name),
            });
            let id_artifact =
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(artifact.id);
            return Ok(vec![id_artifact]);
        }

        // Through the shared gate: a header that did not arrive in full is the
        // stager's record of a short read, never a finding about the file.
        let temp = match seance_sqlite_util::stage_named_store(artifact, "imessage", MAX_DB_BYTES) {
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
            // fails is a message store this tool could not read: from here on
            // every failure is reported, because zero artifacts would make a
            // corrupt chat.db indistinguishable from a device with no messages.
            if !staged_looks_like_sqlite(temp.path()) {
                debug!("{} carries no SQLite header, skipping", name);
                return Ok(Vec::new());
            }

            let conn = temp.open().context("Failed to open iMessage database")?;

            // `?`, not `unwrap_or(false)`: a database whose catalogue cannot be
            // read takes the parse-failure path (which carries the
            // incompleteness pair) rather than being filed as "not a chat.db".
            if !has_imessage_schema(&conn)? {
                info!("{} does not have iMessage schema, skipping", name);
                return Ok(Vec::new());
            }

            parse_messages(&conn, artifact.case_id, artifact.id)
        })();

        match result {
            Ok(mut artifacts) => {
                // The spill knows whether the file was staged whole. Carry that
                // onto the records: SQLite answers queries happily from a
                // truncated file, so a partial database otherwise yields a
                // partial conversation that looks like the whole one.
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!(
                    "IMessageParser extracted {} records from {}",
                    artifacts.len(),
                    name
                );
                Ok(artifacts)
            }
            Err(e) => {
                warn!("Failed to parse iMessage database ({}): {}", name, e);
                let detail = format!(
                    "the iMessage database {name} could not be parsed ({e}); no message from \
                     it is in this case, and their absence here is not evidence they were \
                     absent from the device"
                );
                let metadata = json!({
                    // NOT `"iMessage"` — see the attachment marker above: the
                    // conversation aggregation groups on this key and would
                    // count a parse failure as a message in an `unknown` thread.
                    "type": "iMessageIncomplete",
                    "file_name": name,
                    "status": "ParseFailed",
                    "error": e.to_string(),
                    // The standard pair, not just a status string: the API,
                    // export and reporting paths key on these, and without them
                    // a failed parse exports as a database that held no
                    // messages.
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    // The keys the examiner-facing reader shows the sentence from.
                    "content_incomplete_detail": detail,
                    "inventory_incomplete_detail": detail,
                    "name": format!("iMessage Database (parse failed): {}", name),
                });
                let id_artifact =
                    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(artifact.id);
                Ok(vec![id_artifact])
            }
        }
    }
}
