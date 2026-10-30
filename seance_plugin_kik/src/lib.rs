#![forbid(unsafe_code)]
//! Kik (Android) message parser.
//!
//! [`KikParser`] self-selects Kik's `kikDatabase.db` (SQLite) and emits one
//! `chat_message` [`ParsedRecord`](ArtifactType::ParsedRecord) per row of
//! `messagesTable`, matching the chat-record shape used by the other messaging
//! parsers so Kik conversations appear alongside them.
//!
//! # Schema
//!
//! `messagesTable` carries `_id`, `body`, `partner_jid` (the other party's Kik
//! JID), `was_me` (1 = sent by the device owner) and `timestamp` (Unix
//! **milliseconds**). When present, `KIKcontactsTable` maps each `jid` to a
//! `display_name`, used to give the contact a human name; otherwise the JID is
//! surfaced. Columns are detected at runtime so schema drift degrades gracefully.
//!
//! # Honesty & robustness
//!
//! A non-SQLite file, a missing `messagesTable`, or corrupt rows never panic and
//! never fail the pipeline: whatever parsed is emitted, otherwise an empty result.
//!
//! # Schema support
//!
//! The message columns are read through a `FieldMap` (see `schema_support`),
//! and each parsed store emits one `KikIncomplete` record of `warning_class:
//! ParserStaleWarning`: no validated range (no real Kik Android store is held
//! by this project — `SCHEMA_SUPPORT` says why, and names the iOS Core Data
//! store this parser does not read), the `PRAGMA user_version` the store
//! carries (0 is "not recorded", never version 0), and any logical field no
//! column resolved — the only case that stamps `content_incomplete` (reason
//! `unvalidated`). A renamed `body` or `timestamp` is therefore a named
//! finding, not an empty result.

use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::adopt::app_marker::{open_store, StoreSpec};
use seance_sqlite_util::{
    artifact_name, probe_columns, probe_table, query_failed_marker, unreadable_store_marker,
    ChatMessage, Presence, RowDrops,
};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

mod schema_support;
use schema_support::{field_expr, SchemaBound, SchemaSupport};
#[cfg(test)]
use schema_support::{SchemaCheck, SchemaVersion};
#[cfg(test)]
use seance_sqlite_util::FieldMap;

/// What this parser may say about a Kik schema version.
///
/// Unranged, and it stays so until a real `kikDatabase.db` is opened by this
/// project. The one real Kik database held here —
/// `reference/plaso/test_data/kik_ios.sqlite` — is the iOS Core Data store
/// (`ZKIKMESSAGE`, `PRAGMA user_version` 0, model version in `Z_METADATA`),
/// which this Android parser does not read, so it validates nothing about
/// `messagesTable`. No Android store is in `test_data/`, `~/forensic_corpora`
/// or `~/ctf-evidence` (searched 2026-09-19; the 2019 Magnet ADB backup does
/// not carry it). Once a real store is read, its `PRAGMA user_version` becomes
/// the single-point range `n..=n`, with the file named as evidence.
const SCHEMA_SUPPORT: SchemaSupport = SchemaSupport {
    app: "kik-android",
    bound: SchemaBound::Unranged {
        why: "no reference database of this app is held by this project; the schema version \
              is recorded, not ranged",
    },
};

/// Logical fields of `messagesTable` and the physical columns that have carried
/// each. A column Kik renames is a candidate added here, and until it is, the
/// schema record names the logical field that no longer resolves.
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("id", &["_id"]),
    ("text", &["body"]),
    ("sent_at", &["timestamp"]),
    ("partner", &["partner_jid"]),
    ("from_me", &["was_me"]),
];

/// The fields without which a row is not an evidentiary message.
const REQUIRED_FIELDS: &[&str] = &["text", "sent_at"];

pub struct KikParser;

impl ForensicsModule for KikParser {
    fn id(&self) -> &str {
        "plugin.messaging.kik"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact_name(artifact);
        if !is_kik_db(name) {
            return Ok(Vec::new());
        }
        debug!("KikParser parsing {}", name);
        Ok(seance_sqlite_util::process_named_sqlite_db(
            artifact,
            "kik",
            "KikIncomplete",
            "Kik",
            parse_kik,
        ))
    }
}

/// Self-select Kik's database by filename.
fn is_kik_db(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.rsplit('/').next().unwrap_or(&n) == "kikdatabase.db"
}

/// The record type every finding about the contacts lookup is filed under,
/// never the walk's own `Kik` record type (which would form a phantom thread).
const CONTACT_INCOMPLETE_TYPE: &str = "KikContactIncomplete";

/// Map each contact JID to a display name from `KIKcontactsTable`, if present.
///
/// Returns the map alongside the number of contact rows that would not decode.
/// A lost contact row is a lost identity: the messages that JID sent are then
/// attributed to a bare handle rather than the name the device knew it by, and
/// nothing on the record says the name was available but unreadable (B3-023).
///
/// The third element is the one record about the lookup itself. An absent
/// table is a store shape and owes nothing; a table that could not be looked
/// for, a column list that would not read, or a query that would not prepare
/// or run (a renamed `display_name` included) is "could not look", and used to
/// leave the map empty with no record — every sender a bare JID, as if the
/// device held no names (HUNT-226).
fn load_contacts(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
) -> (HashMap<String, String>, RowDrops, Option<Artifact>) {
    let mut map = HashMap::new();
    let mut drops = RowDrops::new();
    let could_not_look = |detail: String| {
        Some(unreadable_store_marker(
            case_id,
            parent_id,
            CONTACT_INCOMPLETE_TYPE,
            detail,
        ))
    };
    match probe_table(conn, "KIKcontactsTable") {
        Presence::Present => {}
        Presence::Absent => return (map, drops, None),
        Presence::Undetermined(why) => {
            return (
                map,
                drops,
                could_not_look(format!(
                    "whether the Kik store holds a `KIKcontactsTable` could not be established, \
                     so senders are shown by JID: {why}"
                )),
            )
        }
    }
    if let Err(why) = probe_columns(conn, "KIKcontactsTable") {
        return (
            map,
            drops,
            could_not_look(format!(
                "`KIKcontactsTable` is present and its column list would not read, so senders \
                 are shown by JID and no display name was looked up: {why}"
            )),
        );
    }
    let query_failed = |e: rusqlite::Error| {
        Some(query_failed_marker(
            case_id,
            parent_id,
            CONTACT_INCOMPLETE_TYPE,
            "KIKcontactsTable",
            &e.to_string(),
        ))
    };
    let mut stmt = match conn
        .prepare("SELECT jid, display_name FROM KIKcontactsTable WHERE jid IS NOT NULL")
    {
        Ok(stmt) => stmt,
        Err(e) => return (map, drops, query_failed(e)),
    };
    let rows = match stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
    }) {
        Ok(rows) => rows,
        Err(e) => return (map, drops, query_failed(e)),
    };
    for row in rows {
        let (jid, name) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Kik: skipping undecodable KIKcontactsTable row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        if let Some(n) = name.filter(|s| !s.is_empty()) {
            map.insert(jid, n);
        }
    }
    (map, drops, None)
}

fn parse_kik(path: &Path, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    parse_kik_with(path, case_id, parent_id, &SCHEMA_SUPPORT)
}

/// [`parse_kik`] under an explicit schema declaration, so the out-of-range
/// paths are reachable in a test while the crate's own declaration stays
/// Unranged.
fn parse_kik_with(
    path: &Path,
    case_id: Uuid,
    parent_id: Uuid,
    support: &SchemaSupport,
) -> Vec<Artifact> {
    let spec = StoreSpec {
        app: "Kik",
        record_type: "KikIncomplete",
        table: "messagesTable",
        fields: MESSAGE_FIELDS,
        required: REQUIRED_FIELDS,
    };
    // The shared open-and-probe sequence: an answered absence is silence, a store
    // that would not open or would not answer is a record, never a phone without
    // Kik (B8-039).
    let store = match open_store(path, case_id, parent_id, &spec) {
        Ok(store) => store,
        Err(done) => return done,
    };
    let conn = &store.conn;
    let fields = &store.fields;
    let schema = store.check(support, &spec);
    // Body + timestamp are the minimum an evidentiary message needs. With
    // neither, a row would carry nothing evidentiary, so none is invented —
    // but the store is not returned as empty either.
    if fields.column("text").is_none() && fields.column("sent_at").is_none() {
        return schema.marker(case_id, parent_id, 0).into_iter().collect();
    }
    let (contacts, contact_drops, contact_lookup) = load_contacts(conn, case_id, parent_id);

    let id_col = fields.column("id").unwrap_or("rowid");
    let text_col = field_expr(fields, "", "text");
    let ts_col = field_expr(fields, "", "sent_at");
    let partner_col = field_expr(fields, "", "partner");
    let wasme_col = field_expr(fields, "", "from_me");
    let order_col = fields.column("sent_at").unwrap_or(id_col);
    let sql = format!(
        "SELECT {id_col}, {text_col}, {ts_col}, {partner_col}, {wasme_col} \
         FROM messagesTable ORDER BY {order_col}"
    );

    // The table and its columns are established, so a statement that will not
    // prepare or run is a store this tool could not read — never an empty one
    // (HUNT-189).
    let query_failed = |e: rusqlite::Error| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            "KikIncomplete",
            "messagesTable",
            &e.to_string(),
        )];
        out.extend(schema.marker(case_id, parent_id, 0));
        out
    };
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(e) => return query_failed(e),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<i64>>(4)?,
        ))
    });
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => return query_failed(e),
    };

    let mut out = Vec::new();
    // Rows the query returned that could not be decoded. `flatten()` used to
    // swallow these, so the message count read as exact (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (id, body, ts_ms, partner, was_me) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Kik: skipping undecodable messagesTable row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        out.push(build_record(
            case_id, parent_id, id, body, ts_ms, partner, was_me, &contacts,
        ));
    }
    // Counted before either marker joins the list, so a marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        "KikIncomplete",
        "messagesTable",
        recovered,
    ));
    out.extend(contact_drops.marker(
        case_id,
        parent_id,
        CONTACT_INCOMPLETE_TYPE,
        "KIKcontactsTable",
        contacts.len(),
    ));
    out.extend(contact_lookup);
    out.extend(schema.marker(case_id, parent_id, recovered));
    out
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    id: i64,
    body: Option<String>,
    ts_ms: Option<i64>,
    partner_jid: Option<String>,
    was_me: Option<i64>,
    contacts: &HashMap<String, String>,
) -> Artifact {
    // `was_me` is 1 when the device owner sent the row. A NULL — or a schema
    // with no such column at all — never recorded the direction, so it stays
    // unknown instead of being asserted as inbound. `ChatMessage` derives
    // `direction` from this, so the two cannot disagree.
    let is_from_me = was_me.map(|v| v == 1);
    let date_s = ts_ms.filter(|&d| d > 0).map(|d| d.div_euclid(1000));
    // Prefer the display name the roster gave the JID; fall back to the JID
    // itself so an unresolved partner is still identified by what the store
    // holds, never by a placeholder.
    let contact = partner_jid
        .as_deref()
        .and_then(|j| contacts.get(j).cloned())
        .or_else(|| partner_jid.clone());

    ChatMessage::new("Kik", "Kik", "Android")
        .text(body)
        .date_secs(date_s)
        .from_me(is_from_me)
        .chat_identifier(partner_jid)
        .contact(contact)
        .extra("rowid", json!(id))
        .into_artifact(case_id, parent_id)
}

#[cfg(test)]
mod tests;
