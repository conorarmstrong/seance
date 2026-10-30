#![forbid(unsafe_code)]
//! Skype (classic desktop `main.db`) message parser.
//!
//! [`SkypeParser`] self-selects the classic Skype `main.db` and emits one
//! `chat_message` [`ParsedRecord`](ArtifactType::ParsedRecord) per row of the
//! `Messages` table, matching the chat-record shape used by the other messaging
//! parsers so Skype conversations appear alongside them.
//!
//! # Schema
//!
//! `Messages` carries `id`, `author` (sender skypename), `from_dispname`
//! (display name), `dialog_partner`, `timestamp` (Unix **seconds**), `chatname`
//! and `body_xml` (the message text, marked up — tags are stripped and basic
//! entities decoded). The owning account's skypename comes from `Accounts`, which
//! decides message direction.
//!
//! Because `main.db` is a generic filename, an artifact is only parsed once its
//! content is confirmed to be a Skype database (an `Accounts` table carrying
//! `skypename` and a `Messages` table); anything else yields nothing.
//!
//! # Schema version
//!
//! Skype records its schema version in its own `AppSchemaVersion` table
//! (`SQLiteSchemaVersion`), not in `PRAGMA user_version`, which is 0 on the
//! real store on file. The one real store read 66, so the validated range is
//! the single point 66..=66; a store outside it is disclosed, and a column the
//! parser cannot resolve is named, rather than either being silent.
//!
//! # Honesty & robustness
//!
//! Non-Skype / non-SQLite input and corrupt rows never panic and never fail the
//! pipeline: whatever parsed is emitted, otherwise an empty result.

use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    artifact_name, open_readonly, probe_table, stage_sqlite_db, table_columns, ChatMessage,
    FieldMap, Presence, RowDrops, SqliteEntry, SupportedRange, MAX_DB_BYTES,
};
use serde_json::json;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

pub mod schema;
use schema::{assess, Observation, SchemaSupport, SchemaVersion, SupportBound};

pub struct SkypeParser;

/// The record type every Skype incompleteness marker and schema note is filed
/// under — never `"Skype"`, which `seance_db` groups conversations on.
const INCOMPLETE_TYPE: &str = "SkypeIncomplete";

/// Every logical field read from `Messages`, with the physical column(s) that
/// have carried it. The real store on file carries exactly this set.
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("author", &["author"]),
    ("sent_at", &["timestamp"]),
    ("body", &["body_xml"]),
    ("display_name", &["from_dispname"]),
    ("partner", &["dialog_partner"]),
    ("chat", &["chatname"]),
];

/// Without a body and a time a `Messages` row is not a message record.
const MESSAGE_REQUIRED: &[&str] = &["body", "sent_at"];

/// Where Skype keeps its schema version.
const VERSION_LOCATOR: &str = "AppSchemaVersion.SQLiteSchemaVersion";

/// One real store on file, so one point.
const MESSAGE_SUPPORT: SchemaSupport = SchemaSupport {
    app: "skype-desktop",
    store: "main.db",
    table: "Messages",
    record_type: INCOMPLETE_TYPE,
    locator: VERSION_LOCATOR,
    bound: SupportBound::Validated {
        range: SupportedRange {
            min: 66,
            max: Some(66),
        },
        evidence: "AppSchemaVersion.SQLiteSchemaVersion 66 (ClientVersion \
                   0/6.6.0.106//_checksum_3768521794) read from one real store: plaso's test \
                   database skype_main.db (15 Messages rows; PRAGMA user_version is 0 on it); \
                   a single-point range because one file was seen",
    },
};

/// Skype's schema version, three-valued: the app's own table, not
/// `PRAGMA user_version`, which the real store leaves at 0.
fn read_app_schema_version(conn: &Connection) -> SchemaVersion {
    match probe_table(conn, "AppSchemaVersion") {
        Presence::Absent => return SchemaVersion::NotRecorded,
        Presence::Undetermined(why) => return SchemaVersion::Undetermined(why),
        Presence::Present => {}
    }
    use rusqlite::types::Value;
    match conn.query_row(
        "SELECT SQLiteSchemaVersion FROM AppSchemaVersion LIMIT 1",
        [],
        |r| r.get::<_, Value>(0),
    ) {
        Ok(Value::Integer(v)) => SchemaVersion::Found(v),
        Ok(Value::Text(t)) => match t.trim().parse::<i64>() {
            Ok(v) => SchemaVersion::Found(v),
            Err(_) => SchemaVersion::Undetermined(format!(
                "`{VERSION_LOCATOR}` holds {t:?}, which is not a version number"
            )),
        },
        Ok(Value::Null) => SchemaVersion::NotRecorded,
        Ok(other) => SchemaVersion::Undetermined(format!(
            "`{VERSION_LOCATOR}` holds a {} value, not a version number",
            other.data_type()
        )),
        Err(rusqlite::Error::QueryReturnedNoRows) => SchemaVersion::NotRecorded,
        Err(e) => SchemaVersion::Undetermined(format!("`{VERSION_LOCATOR}` would not read: {e}")),
    }
}

impl ForensicsModule for SkypeParser {
    fn id(&self) -> &str {
        "plugin.messaging.skype"
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
        if !is_main_db(name) {
            return Ok(Vec::new());
        }

        debug!("SkypeParser inspecting {}", name);
        // The shared gate skips directories and artifacts with no reachable
        // content, probes the SQLite magic with a LOOPING read (a windowed or
        // container-backed source may answer a 16-byte request with 4, and a
        // single `read_at` would file a real Skype database as "not SQLite"),
        // then stages the database with its `-wal` sibling and records whether
        // it was staged in full. SQLite opens a truncated file and answers from
        // the pages it can reach, so without that record the surviving rows
        // read as the whole conversation store (B2-124).
        // NO "unreadable store" record on `SqliteEntry::StagingFailed` here, and
        // that is deliberate: Skype's only selector is the filename `main.db`,
        // which dozens of unrelated apps also use. This parser does not know the
        // file is Skype's until it opens it and finds the `Messages` table, so a
        // marker emitted before that would assert a Skype store was on the
        // device on the strength of a generic name — a claim the evidence does
        // not support, and one that would fire on ordinary cases. The plugins
        // whose filenames identify the app on their own (Viber, Kik, WeChat,
        // LINE, Messenger, Twitter, Instagram, Snapchat's `arroyo.db`) DO emit
        // it; see `unreadable_store_marker`.
        let SqliteEntry::Staged(temp) = stage_sqlite_db(artifact, "skype", MAX_DB_BYTES) else {
            return Ok(Vec::new());
        };
        let mut out = parse_skype(temp.path(), artifact.case_id, artifact.id);
        // `main.db` is a common filename, so a database that yielded nothing is
        // usually another app's and not ours to comment on — unless the file
        // itself could not be staged whole, which is worth saying either way.
        if !out.is_empty() || temp.content_incomplete_reason().is_some() {
            temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        }
        Ok(out)
    }
}

/// Skype's store is the generically-named `main.db`; content confirms it.
fn is_main_db(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.rsplit('/').next().unwrap_or(&n) == "main.db"
}

fn parse_skype(path: &Path, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    let Ok(conn) = open_readonly(path) else {
        return Vec::new();
    };

    // Confirm this is a Skype database, not some other main.db: `skypename`
    // is Skype's own vocabulary. The signature is deliberately NOT the body
    // column, so a store whose body column was renamed is still recognised as
    // Skype's and the rename is reported rather than read as "not Skype".
    if !table_columns(&conn, "Accounts").contains("skypename") {
        return Vec::new();
    }
    let msg_cols = table_columns(&conn, "Messages");
    if msg_cols.is_empty() {
        return Vec::new();
    }

    let owner = conn
        .query_row(
            "SELECT skypename FROM Accounts WHERE skypename IS NOT NULL LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok();

    let fields = FieldMap::resolve(&msg_cols, MESSAGE_FIELDS);
    let version = read_app_schema_version(&conn);
    let assessment = |recovered: usize| {
        let obs = Observation {
            version: version.clone(),
            fields: Some(&fields),
            required: MESSAGE_REQUIRED,
            recovered,
        };
        assess(&MESSAGE_SUPPORT, &obs, case_id, parent_id)
    };
    // A `Messages` table with neither a body nor a time is not the one this
    // parser knows; say so rather than manufacture rows from it.
    if MESSAGE_REQUIRED.iter().all(|f| fields.column(f).is_none()) {
        return assessment(0);
    }
    let id_col = if msg_cols.contains("id") {
        "id"
    } else {
        "rowid"
    };
    // Every `NULL` below stands for a logical field the map recorded as
    // unresolved and the assessment names. `chat` is Skype's conversation key
    // (e.g. "#alice/$bob;abc"); without it every message lands in one pile
    // (BUG-225), which is why its absence is disclosed rather than passed over.
    let col = |logical: &str| fields.column(logical).unwrap_or("NULL");
    let author = col("author");
    let sent_at = col("sent_at");
    let body = col("body");
    let disp = col("display_name");
    let partner = col("partner");
    let chat = col("chat");
    let sql = format!(
        "SELECT {id_col}, {author}, {sent_at}, {body}, {disp}, {partner}, {chat} \
         FROM Messages ORDER BY {sent_at}"
    );

    let Ok(mut stmt) = conn.prepare(&sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, Option<String>>(6)?,
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };

    let mut out = Vec::new();
    // Rows the query returned that could not be decoded into the tuple above
    // (unexpected column type on a partially recovered page, a NULL where the
    // schema promised none). `flatten()` used to swallow these, so the message
    // count read as exact (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (id, author, ts, body_xml, dispname, partner, chatname) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skype: skipping undecodable Messages row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        out.push(build_record(
            case_id,
            parent_id,
            id,
            author,
            ts,
            body_xml,
            dispname,
            partner,
            chatname,
            owner.as_deref(),
        ));
    }
    // Counted before the marker joins the list, so the marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(case_id, parent_id, INCOMPLETE_TYPE, "Messages", recovered));
    out.extend(assessment(recovered));
    out
}

/// Strip markup tags from a Skype `body_xml` and decode the basic XML entities.
fn strip_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = (depth - 1).max(0),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    // Decode entities; &amp; last so it can't double-decode the others.
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
        .trim()
        .to_string()
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    id: i64,
    author: Option<String>,
    ts: Option<i64>,
    body_xml: Option<String>,
    dispname: Option<String>,
    partner: Option<String>,
    chatname: Option<String>,
    owner: Option<&str>,
) -> Artifact {
    // Direction needs both the row's author and the account owner (skypename).
    // Without one of them it was never established, so it stays unknown rather
    // than being asserted as inbound — an outgoing message reported as received
    // inverts the record silently. `ChatMessage` derives `direction` from this
    // single value, so the two cannot disagree.
    let is_from_me: Option<bool> = match (author.as_deref(), owner) {
        (Some(a), Some(o)) => Some(a == o),
        _ => None,
    };
    let date_s = ts.filter(|&d| d > 0);
    let text = body_xml.as_deref().map(strip_xml).filter(|s| !s.is_empty());
    let contact = dispname
        .filter(|s| !s.is_empty())
        .or_else(|| author.clone())
        .or_else(|| partner.clone());
    // Conversation key. Prefer Skype's own `chatname`; fall back to the 1:1
    // dialog partner so at least direct chats group. Omitted when neither is
    // present rather than invented.
    let chat_key = chatname
        .filter(|s| !s.is_empty())
        .or_else(|| partner.filter(|s| !s.is_empty()));

    ChatMessage::new("Skype", "Skype", "Desktop")
        .text(text)
        .date_secs(date_s)
        .from_me(is_from_me)
        .contact(contact)
        .chat_identifier(chat_key)
        .extra("rowid", json!(id))
        .extra("author", json!(author.filter(|s| !s.is_empty())))
        .into_artifact(case_id, parent_id)
}

#[cfg(test)]
mod tests;
