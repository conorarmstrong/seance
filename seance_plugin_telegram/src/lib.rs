#![forbid(unsafe_code)]
//! Telegram (Android `cache4.db`) message-metadata parser.
//!
//! [`TelegramParser`] self-selects Telegram's `cache4.db` and reads the plain
//! columns of the `messages_v2` (or legacy `messages`) table — dialog, date and
//! direction — into `chat_message`
//! [`ParsedRecord`](ArtifactType::ParsedRecord)s, building a Telegram
//! communication timeline (who/when/direction).
//!
//! # What is and isn't decoded
//!
//! Each row's message **text** lives in the `data` BLOB as a **TL-serialized**
//! object whose layout is version-specific. `tl::message_text` recovers it
//! without assuming that layout: it anchors on the row's own `date` column,
//! which `message:string` follows in every layer, and reads the body with TL's
//! fixed string framing (see `tl.rs`). A row whose blob does not resolve
//! unambiguously keeps an **absent** body rather than a guessed one, so every
//! record says which happened — `text_recovered` plus `content_encoding`. The
//! dialog, timestamp and direction are read from ordinary integer columns and
//! are exact.
//!
//! # Schema
//!
//! `messages_v2`: `mid`, `uid` (dialog id; negative for groups/channels),
//! `date` (Unix **seconds**), `out` (1 = outgoing, 0 = incoming), `data` (TL blob).
//!
//! When `out` is NULL, or the build's schema has no `out` column, the direction
//! was never recorded: `direction` / `is_from_me` are **omitted** rather than
//! defaulted to "received", so a sent/received graph never attributes a message
//! to the wrong party.
//!
//! # Honesty & robustness
//!
//! A non-Telegram file, a missing message table, or corrupt rows never panic and
//! never fail the pipeline.
//!
//! # Schema support
//!
//! The message columns are read through a `FieldMap` (see `schema_support`),
//! and each parsed store emits one `TelegramMessageIncomplete` record of
//! `warning_class: ParserStaleWarning`: no validated range (no real cache4.db
//! is held by this project — `SCHEMA_SUPPORT` says why), the `PRAGMA
//! user_version` the store carries (0 is "not recorded", never version 0), and
//! any logical field no column resolved — the only case that stamps
//! `content_incomplete` (reason `unvalidated`).

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    artifact_name, open_readonly, stage_sqlite_db, table_columns, unreadable_store_marker,
    ChatMessage, FieldMap, RowDrops, SqliteEntry, MAX_DB_BYTES,
};
use serde_json::json;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

mod schema_support;
mod tl;
#[cfg(test)]
use schema_support::SchemaVersion;
use schema_support::{field_expr, user_version, SchemaBound, SchemaCheck, SchemaSupport};

/// What this parser may say about a Telegram schema version.
///
/// Unranged, and it stays so until a real `cache4.db` is opened by this
/// project: none is held in `test_data/`, `reference/plaso/test_data`,
/// `~/forensic_corpora` or `~/ctf-evidence` (searched 2026-09-19; the Android
/// 14 reference image the 34 Telegram messages came from is not on
/// disk). A range declared from documentation would be a claim about
/// databases this project has never opened. Once a real store is read, its
/// `PRAGMA user_version` becomes the single-point range `n..=n`, with the file
/// named as evidence.
const SCHEMA_SUPPORT: SchemaSupport = SchemaSupport {
    app: "telegram-android",
    bound: SchemaBound::Unranged {
        why: "no reference database of this app is held by this project; the schema version \
              is recorded, not ranged",
    },
};

/// Logical fields of the message table and the physical columns that have
/// carried each. A column Telegram renames is a candidate added here, and until
/// it is, the schema record names the logical field that no longer resolves.
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("id", &["mid"]),
    ("dialog", &["uid"]),
    ("sent_at", &["date"]),
    ("from_me", &["out"]),
    ("body", &["data"]),
];

/// The fields without which a row is not an evidentiary message: the `date`
/// is also the anchor the body is recovered from.
const REQUIRED_FIELDS: &[&str] = &["dialog", "sent_at"];

/// How many characters of a recovered body go into the one-line label.
const PREVIEW_CHARS: usize = 60;

pub struct TelegramParser;

impl ForensicsModule for TelegramParser {
    fn id(&self) -> &str {
        "plugin.messaging.telegram"
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
        if !is_telegram_db(name) {
            return Ok(Vec::new());
        }

        debug!("TelegramParser inspecting {name}");
        // The shared gate skips directories and artifacts with no reachable
        // content and probes the magic BEFORE staging, so a non-SQLite file
        // named cache4.db is not spilled at all. The probe LOOPS over short
        // reads: a windowed / container-backed source is entitled to return
        // fewer bytes than asked for, and a single `read_at` that came back with
        // 8 bytes would file a real cache4.db as "not a database" and drop the
        // whole store. Staging brings the `-wal` along — Telegram's cache4.db is
        // usually seized with recent messages still uncheckpointed — and records
        // whether the database itself was taken in full: one over the byte cap,
        // or one whose source stops early, still opens and answers queries, so
        // without that record its surviving rows read as the whole store.
        let temp = match stage_sqlite_db(artifact, "telegram", MAX_DB_BYTES) {
            SqliteEntry::Staged(temp) => temp,
            // The file is named cache4.db and carries the SQLite header, so a
            // staging failure here is a Telegram store this tool did not
            // examine. Returning nothing for it would put "no Telegram
            // messages" in the case.
            SqliteEntry::StagingFailed(e) => {
                return Ok(vec![unreadable_marker(
                    artifact.case_id,
                    artifact.id,
                    format!("the cache4.db could not be staged for examination: {e}"),
                )])
            }
            _ => return Ok(Vec::new()),
        };
        let mut out = parse_messages(temp.path(), artifact.case_id, artifact.id);
        temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        Ok(out)
    }
}

fn is_telegram_db(name: &str) -> bool {
    name.to_ascii_lowercase().rsplit('/').next().unwrap_or("") == "cache4.db"
}

fn parse_messages(path: &Path, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    parse_messages_with(path, case_id, parent_id, &SCHEMA_SUPPORT)
}

/// [`parse_messages`] under an explicit schema declaration, so the
/// out-of-range paths are reachable in a test while the crate's own
/// declaration stays Unranged.
fn parse_messages_with(
    path: &Path,
    case_id: Uuid,
    parent_id: Uuid,
    support: &SchemaSupport,
) -> Vec<Artifact> {
    // The caller has already verified the SQLite header, so a store that will
    // not open or will not answer is one this tool could not read — reported,
    // never returned as an empty history.
    let conn = match open_readonly(path) {
        Ok(c) => c,
        Err(e) => {
            return vec![unreadable_marker(
                case_id,
                parent_id,
                format!("the staged cache4.db would not open: {e}"),
            )]
        }
    };
    // `table_columns` cannot tell "no such table" from "the catalogue would not
    // read", and the two must never render the same: the second is a corrupt
    // store, which would otherwise be filed as "not a Telegram schema" and
    // produce nothing at all. Ask the catalogue directly first.
    if let Err(e) = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    }) {
        return vec![unreadable_marker(
            case_id,
            parent_id,
            format!("the schema catalogue would not read: {e}"),
        )];
    }
    // messages_v2 on modern Telegram; messages on older builds.
    let table = if !table_columns(&conn, "messages_v2").is_empty() {
        "messages_v2"
    } else {
        "messages"
    };
    let cols = table_columns(&conn, table);
    if cols.is_empty() {
        // `table_columns` returns an empty set both for "no such table" and for
        // "the column list would not read". The catalogue answered a moment ago,
        // so ask it which of the two this is: a message table that IS listed and
        // whose columns will not read is a damaged store, and returning nothing
        // for it would file it as a Telegram install with no history.
        // Fail closed on `Err`: the catalogue answered a moment ago, so one that
        // will not answer now is a damaged store, never "no such table".
        return match conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |r| r.get::<_, bool>(0),
        ) {
            Ok(false) => Vec::new(), // not a Telegram schema at all: silence.
            Ok(true) => vec![unreadable_marker(
                case_id,
                parent_id,
                format!("`{table}` is present and its column list would not read"),
            )],
            Err(e) => vec![unreadable_marker(
                case_id,
                parent_id,
                format!("the catalogue stopped answering while looking for `{table}`: {e}"),
            )],
        };
    }
    // Logical fields resolved against the columns actually present. A renamed
    // column used to fail the `date`/`uid` check below and return nothing —
    // which renders exactly like an account with no Telegram history. Now it
    // is a record naming the field, and the rows are still read for what
    // resolves.
    let fields = FieldMap::resolve(&cols, MESSAGE_FIELDS);
    let schema = SchemaCheck {
        support,
        version: user_version(&conn),
        fields: &fields,
        required: REQUIRED_FIELDS,
        record_type: "TelegramMessageIncomplete",
        store: table,
    };
    // With neither the dialog nor the date, a row would carry nothing
    // evidentiary, so none is invented — but the store is not returned as
    // empty either.
    if fields.column("dialog").is_none() && fields.column("sent_at").is_none() {
        return schema.marker(case_id, parent_id, 0).into_iter().collect();
    }
    let id_col = fields.column("id").unwrap_or("rowid");
    let uid_col = field_expr(&fields, "", "dialog");
    let date_col = field_expr(&fields, "", "sent_at");
    let out_col = field_expr(&fields, "", "from_me");
    // The message body is inside `data`. A schema without that column simply
    // has no body to recover; it is not a reason to skip the row's exact
    // metadata.
    let data_col = field_expr(&fields, "", "body");
    let order_col = fields.column("sent_at").unwrap_or(id_col);
    let sql = format!(
        "SELECT {id_col}, {uid_col}, {date_col}, {out_col}, {data_col} FROM {table} \
         ORDER BY {order_col}"
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            return vec![unreadable_marker(
                case_id,
                parent_id,
                format!("the `{table}` message query would not prepare: {e}"),
            )]
        }
    };
    let rows = stmt.query_map([], |r| {
        // The body is copied only where the column really holds a BLOB. A
        // `data` column carrying something else is not a row-decode failure —
        // the plain columns beside it are still exact — so it must not join the
        // dropped-row count below and inflate what was lost.
        let data = match r.get_ref(4)? {
            rusqlite::types::ValueRef::Blob(b) => Some(b.to_vec()),
            _ => None,
        };
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<i64>>(1)?,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<i64>>(3)?,
            data,
        ))
    });
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            return vec![unreadable_marker(
                case_id,
                parent_id,
                format!("the `{table}` message walk would not run: {e}"),
            )]
        }
    };
    let mut out = Vec::new();
    let mut drops = RowDrops::new();
    for row in rows {
        // Counted, never merely skipped: the number of records this walk
        // produces is what an examiner reads as the size of the Telegram
        // history, and a row that would not decode is a message that existed
        // and was not recovered (B3-023 class).
        let (mid, uid, date_s, out_flag, data) = match row {
            Ok(r) => r,
            Err(e) => {
                drops.record(&e);
                debug!("Telegram: {table} row would not decode: {e}");
                continue;
            }
        };
        out.push(build_record(
            case_id, parent_id, mid, uid, date_s, out_flag, data,
        ));
    }
    // Counted before the marker joins the list, so the marker never counts
    // itself as a recovered record. The marker's type is deliberately NOT
    // "TelegramMessage": `seance_db` groups conversations by `metadata.$.type`,
    // and reusing the message type would file this marker as a message and
    // invent a one-message conversation.
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        "TelegramMessageIncomplete",
        table,
        recovered,
    ));
    out.extend(schema.marker(case_id, parent_id, recovered));
    out
}

/// The record that says a Telegram store was identified and could not be read.
/// Zero artifacts would render identically to an account with no messages.
///
/// The type is `TelegramMessageIncomplete`, never `TelegramMessage`: `seance_db`
/// groups conversations by `metadata.$.type`. It deliberately carries no
/// `service` / `platform` key either — those are the messaging-record keys
/// `chat_timeline_row` falls back to when `type` is absent, and no consumer
/// reads them on a `parse_incomplete` record, so the only thing they can do is
/// make this marker resemble a message.
/// Delegates to the shared builder rather than keeping a fourteenth hand-rolled
/// copy of the same metadata. The local copy stamped the sentence only on a
/// bare `detail` key, which the examiner-facing reader
/// (`frontend/src/lib/incompleteness.ts`) does not look at — it keys off
/// `content_incomplete_detail` / `inventory_incomplete_detail`. The shared
/// builder writes all three, so the sentence explaining WHY the store was
/// unreadable now reaches the surface that shows the stamp.
fn unreadable_marker(case_id: Uuid, parent_id: Uuid, detail: String) -> Artifact {
    unreadable_store_marker(case_id, parent_id, "TelegramMessageIncomplete", detail)
}

/// The opening of a recovered body, for the one-line label.
///
/// Bounded by characters rather than bytes: a byte slice of a body carrying an
/// emoji or an accent would cut mid-codepoint and panic.
fn label_preview(text: &str) -> String {
    text.chars().take(PREVIEW_CHARS).collect()
}

fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    mid: i64,
    uid: Option<i64>,
    date_s: Option<i64>,
    out_flag: Option<i64>,
    data: Option<Vec<u8>>,
) -> Artifact {
    // `out` is 1 for a message the device owner sent, 0 for one they received.
    // A NULL — or a schema with no `out` column at all — never recorded the
    // direction, so it stays unknown rather than being asserted as inbound.
    // Attributing a message to the wrong party is among the most consequential
    // errors this tool can make (B2-083); `ChatMessage` derives `direction`
    // from this single value, so the two can never disagree.
    let is_from_me = out_flag.map(|v| v == 1);
    let dialog = uid.map(|u| u.to_string());
    let date = date_s.filter(|&d| d > 0);

    // The body is inside the TL blob and is recovered only where the row's own
    // `date` anchors the field unambiguously (see `tl.rs`). A row whose blob
    // does not resolve keeps an absent body rather than a guessed one.
    let text = match (data.as_deref(), date) {
        (Some(blob), Some(d)) => tl::message_text(blob, d),
        _ => None,
    };
    // A `false` here is a finding in its own right: the row had a body this
    // parser could not resolve, not a message that said nothing. `text` is
    // never `Some("")` — an empty candidate is refused — so the flag and the
    // presence of the `text` key cannot disagree.
    let text_recovered = text.is_some();
    let encoding = if text_recovered {
        "TL-serialized (message text recovered)"
    } else {
        "TL-serialized (not decoded)"
    };
    let preview = text.as_deref().map(label_preview);

    let msg = ChatMessage::new("TelegramMessage", "Telegram", "Android")
        .text(text)
        .date_secs(date)
        .from_me(is_from_me)
        .chat_identifier(dialog.clone())
        .extra("mid", json!(mid))
        .extra("content_encoding", json!(encoding))
        .extra("text_recovered", json!(text_recovered));
    // The derived label reads "(no text)" for every row whose blob did not
    // resolve, which is true but useless when the dialog is the only thing
    // distinguishing them; where the body *was* recovered it belongs in the
    // label like every other messaging record's.
    let direction = msg.direction().unwrap_or("message");
    let dialog_label = dialog.as_deref().unwrap_or("?");
    let display = match preview {
        Some(p) => format!("Telegram {direction} in dialog {dialog_label}: {p}"),
        None => format!("Telegram {direction} in dialog {dialog_label}"),
    };
    msg.display(display).into_artifact(case_id, parent_id)
}

#[cfg(test)]
mod tests;
