#![forbid(unsafe_code)]
//! Viber (Android) message parser.
//!
//! [`ViberParser`] self-selects Viber's message store (`viber_messages` /
//! `viber_data`, a SQLite database) and emits one `chat_message`
//! [`ParsedRecord`](ArtifactType::ParsedRecord) per row of the `messages` table,
//! matching the chat-record shape used by the other messaging parsers (iMessage,
//! WhatsApp, Signal, Android SMS) so Viber conversations appear alongside them.
//!
//! # Schema
//!
//! The `messages` table carries `_id`, `body`, `date` (Unix **milliseconds**), a
//! direction column (`send_type` — 1 outgoing, 0 incoming — or, on older builds,
//! `type`), and `conversation_id`. Columns are detected at runtime so schema
//! drift across Viber versions degrades gracefully rather than failing.
//!
//! Contact/number resolution (Viber spreads it across `participants` /
//! `participants_info` with version-specific joins) is intentionally left to a
//! follow-up; `conversation_id` is surfaced so messages still group per chat.
//!
//! # Honesty & robustness
//!
//! A non-SQLite file, a missing `messages` table, or corrupt rows never panic and
//! never fail the pipeline: whatever parsed is emitted, otherwise an empty result.
//!
//! # Schema support
//!
//! The message columns are read through a `FieldMap` (see `schema_support`),
//! and each parsed store emits one `ViberIncomplete` record of `warning_class:
//! ParserStaleWarning`: no validated range (no real Viber store is held by this
//! project — `SCHEMA_SUPPORT` says why), the `PRAGMA user_version` the store
//! carries (0 is "not recorded", never version 0), and any logical field no
//! column resolved — the only case that stamps `content_incomplete` (reason
//! `unvalidated`). A renamed `body` or `date` is therefore a named finding, not
//! an empty result.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::adopt::app_marker::{open_store, StoreSpec};
use seance_sqlite_util::{artifact_name, query_failed_marker, ChatMessage, RowDrops};
use serde_json::json;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

mod schema_support;
use schema_support::{field_expr, SchemaBound, SchemaSupport};
#[cfg(test)]
use schema_support::{SchemaCheck, SchemaVersion};
#[cfg(test)]
use seance_sqlite_util::FieldMap;

/// What this parser may say about a Viber schema version.
///
/// Unranged, and it stays so until a real `viber_messages` store is opened by
/// this project: none is held in `test_data/`, `reference/plaso/test_data`,
/// `~/forensic_corpora` or `~/ctf-evidence` (searched 2026-09-19). A range
/// declared from documentation would be a claim about databases this project
/// has never opened. Once a real store is read, its `PRAGMA user_version`
/// becomes the single-point range `n..=n`, with the file named as evidence.
const SCHEMA_SUPPORT: SchemaSupport = SchemaSupport {
    app: "viber-android",
    bound: SchemaBound::Unranged {
        why: "no reference database of this app is held by this project; the schema version \
              is recorded, not ranged",
    },
};

/// Logical fields of the `messages` table and the physical columns that have
/// carried each. A column Viber renames is a candidate added here, and until it
/// is, the schema record names the logical field that no longer resolves.
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("id", &["_id"]),
    ("text", &["body"]),
    ("sent_at", &["date"]),
    ("from_me", &["send_type", "type"]),
    ("conversation", &["conversation_id"]),
];

/// The fields without which a row is not an evidentiary message.
const REQUIRED_FIELDS: &[&str] = &["text", "sent_at"];

pub struct ViberParser;

impl ForensicsModule for ViberParser {
    fn id(&self) -> &str {
        "plugin.messaging.viber"
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
        if !is_viber_db(name) {
            return Ok(Vec::new());
        }
        debug!("ViberParser parsing {}", name);
        Ok(seance_sqlite_util::process_named_sqlite_db(
            artifact,
            "viber",
            "ViberIncomplete",
            "Viber",
            parse_viber,
        ))
    }
}

/// Self-select Viber's message store by filename.
fn is_viber_db(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let base = n.rsplit('/').next().unwrap_or(&n);
    base == "viber_messages" || base == "viber_data"
}

fn parse_viber(path: &Path, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    parse_viber_with(path, case_id, parent_id, &SCHEMA_SUPPORT)
}

/// [`parse_viber`] under an explicit schema declaration, so the out-of-range
/// paths are reachable in a test while the crate's own declaration stays
/// Unranged.
fn parse_viber_with(
    path: &Path,
    case_id: Uuid,
    parent_id: Uuid,
    support: &SchemaSupport,
) -> Vec<Artifact> {
    let spec = StoreSpec {
        app: "Viber",
        record_type: "ViberIncomplete",
        table: "messages",
        fields: MESSAGE_FIELDS,
        required: REQUIRED_FIELDS,
    };
    // The shared open-and-probe sequence: an answered absence is silence, a store
    // that would not open or would not answer is a record, never a phone without
    // Viber (B8-039).
    let store = match open_store(path, case_id, parent_id, &spec) {
        Ok(store) => store,
        Err(done) => return done,
    };
    let conn = &store.conn;
    let fields = &store.fields;
    let schema = store.check(support, &spec);
    // Body + date are the minimum an evidentiary message needs. With neither,
    // a row would carry nothing evidentiary, so none is invented — but the
    // store is not returned as empty either.
    if fields.column("text").is_none() && fields.column("sent_at").is_none() {
        return schema.marker(case_id, parent_id, 0).into_iter().collect();
    }
    let id_col = fields.column("id").unwrap_or("rowid");
    let text_col = field_expr(fields, "", "text");
    let date_col = field_expr(fields, "", "sent_at");
    let dir_col = field_expr(fields, "", "from_me");
    let conv_col = field_expr(fields, "", "conversation");
    let order_col = fields.column("sent_at").unwrap_or(id_col);
    let sql = format!(
        "SELECT {id_col}, {text_col}, {date_col}, {dir_col}, {conv_col} FROM messages \
         ORDER BY {order_col}"
    );

    // The table and its columns are established, so a statement that will not
    // prepare or run is a store this tool could not read — never an empty one
    // (HUNT-189).
    let query_failed = |e: rusqlite::Error| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            "ViberIncomplete",
            "messages",
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
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<i64>>(4)?,
        ))
    });
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => return query_failed(e),
    };

    let mut out = Vec::new();
    // Rows the query returned that could not be decoded (unexpected column type
    // on a partially recovered page, a NULL where the schema promised none).
    // `flatten()` used to swallow these, so the message count read as exact
    // (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (id, body, date_ms, dir, conv) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Viber: skipping undecodable messages row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        out.push(build_record(
            case_id, parent_id, id, body, date_ms, dir, conv,
        ));
    }
    // Counted before either marker joins the list, so neither counts itself
    // as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(case_id, parent_id, "ViberIncomplete", "messages", recovered));
    out.extend(schema.marker(case_id, parent_id, recovered));
    out
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    id: i64,
    body: Option<String>,
    date_ms: Option<i64>,
    dir: Option<i64>,
    conv: Option<i64>,
) -> Artifact {
    // Viber send_type/type: 1 = outgoing (sent by the device owner). A NULL —
    // or a build with no direction column at all — never recorded it, so it
    // stays unknown rather than being asserted as inbound. `ChatMessage`
    // derives `direction` from this, so the two cannot disagree.
    let is_from_me = dir.map(|v| v == 1);
    let date_s = date_ms.filter(|&d| d > 0).map(|d| d.div_euclid(1000));

    // Viber's own numeric conversation key. Left under `conversation_id`
    // rather than `chat_identifier`: `seance_db`'s generic thread key already
    // coalesces onto it, and renaming it would hide the column name the store
    // actually uses. A null is dropped by `extra`, so a build without the
    // column emits no key rather than an empty one.
    ChatMessage::new("Viber", "Viber", "Android")
        .text(body)
        .date_secs(date_s)
        .from_me(is_from_me)
        .extra("rowid", json!(id))
        .extra("conversation_id", json!(conv))
        .into_artifact(case_id, parent_id)
}

#[cfg(test)]
mod tests;
