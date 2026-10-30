#![forbid(unsafe_code)]
//! Instagram Direct message parser.
//!
//! [`InstagramParser`] self-selects Instagram's Android Direct database
//! (`direct.db`, from `com.instagram.android/databases/`) and reads the
//! `messages` table — joined to `threads` for conversation grouping — into
//! `chat_message` [`ParsedRecord`](ArtifactType::ParsedRecord)s that render in
//! the existing Conversation / Comms views.
//!
//! # What is and isn't decoded
//!
//! - **Android** (`direct.db`) is a plain SQLite store: message **text** lives
//!   in the `text` column and is recovered directly; media messages carry a
//!   `message` JSON blob whose media URL/type is surfaced. Timestamps are Unix
//!   epoch **microseconds**. This is the productive path and what this module
//!   implements.
//! - **iOS** (`DirectSQLiteDatabase/<userid>.db`) stores each message body as an
//!   `NSKeyedArchiver` binary-plist BLOB in a `messages.archive` column; that
//!   decode is not done here yet (records would carry no text), so the iOS store
//!   is deliberately not selected.
//!
//! Instagram churns this schema across app versions, so every column is
//! resolved through a field map and a column the schema lacks is **named** on
//! a schema note rather than silently read as empty — a non-Instagram file, a
//! missing table, or a corrupt row never panics and never fails the pipeline.
//!
//! # Schema version
//!
//! No real Instagram `direct.db` is held by this project, so this parser
//! declares **no validated schema range**: a range endpoint not read out of a
//! real file would be a number copied from somewhere. It records the
//! `PRAGMA user_version` it sees on a `schema_support` note and states that it
//! was compared against nothing. The declaration gains a range when a device
//! sample arrives.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    artifact_name, open_readonly, probe_catalogue, probe_columns, probe_table, query_failed_marker,
    unix_seconds_from_magnitude, unreadable_store_marker, ChatMessage, FieldMap, Presence,
    RowDrops,
};
use serde_json::{json, Value};

use std::path::Path;
use tracing::debug;
use uuid::Uuid;

pub mod schema;
use schema::{
    assess, read_user_version, Observation, SchemaSupport, SupportBound, USER_VERSION_LOCATOR,
};

pub struct InstagramParser;

/// The record type every Instagram incompleteness marker and schema note is
/// filed under — never `"Instagram"`, which `seance_db` groups conversations on.
const INCOMPLETE_TYPE: &str = "InstagramIncomplete";

/// Every logical field read from `messages`, with the physical column(s) that
/// have carried it. `message_type` is a STRING on real installs (e.g. "text",
/// "video_call_event"); the account owner is `user_id` and the per-message
/// direction lives inside the `message` JSON as `is_sent_by_viewer`.
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("sent_at", &["timestamp"]),
    ("text", &["text"]),
    ("account", &["user_id"]),
    ("thread", &["thread_id"]),
    ("message_json", &["message"]),
    ("message_type", &["message_type"]),
];

/// Without these a `messages` row is not a Direct message record: when, in
/// which thread, its text, and the JSON that carries its direction.
const MESSAGE_REQUIRED: &[&str] = &["sent_at", "text", "thread", "message_json"];

const MESSAGE_SUPPORT: SchemaSupport = SchemaSupport {
    app: "instagram-android",
    store: "direct.db",
    table: "messages",
    record_type: INCOMPLETE_TYPE,
    locator: USER_VERSION_LOCATOR,
    bound: SupportBound::Unranged {
        why: "no real Instagram Direct database is held by this project, so no schema version \
              has been read out of one; the version seen is recorded, not ranged",
    },
};

impl ForensicsModule for InstagramParser {
    fn id(&self) -> &str {
        "plugin.messaging.instagram"
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
        if !is_instagram_db(name) {
            return Ok(Vec::new());
        }
        debug!("InstagramParser inspecting {name}");
        Ok(seance_sqlite_util::process_named_sqlite_db(
            artifact,
            "instagram",
            INCOMPLETE_TYPE,
            "Instagram",
            parse_direct,
        ))
    }
}

/// Instagram's Android Direct database, matched on filename (never on path, so
/// it fires the same on a raw file system or an extracted backup).
fn is_instagram_db(name: &str) -> bool {
    name.to_ascii_lowercase().rsplit('/').next().unwrap_or("") == "direct.db"
}

/// Read a column as text whether it was stored with TEXT or BLOB affinity.
/// Instagram's `message` JSON is stored as a BLOB on real installs, so a plain
/// `get::<String>` fails with `InvalidColumnType`; fall back to the raw bytes
/// decoded as (lossy) UTF-8. Returns `None` for NULL or a non-text type.
fn col_text(r: &rusqlite::Row, idx: usize) -> Option<String> {
    if let Ok(s) = r.get::<_, Option<String>>(idx) {
        return s;
    }
    r.get::<_, Option<Vec<u8>>>(idx)
        .ok()
        .flatten()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// The record that says a Instagram store was identified and could not be read.
/// Zero artifacts would render identically to a device that never had Instagram.
fn unreadable(case_id: Uuid, parent_id: Uuid, detail: String) -> Vec<Artifact> {
    vec![unreadable_store_marker(
        case_id,
        parent_id,
        INCOMPLETE_TYPE,
        detail,
    )]
}

fn parse_direct(path: &Path, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    // Named as Instagram Direct evidence, so a store that will not open or will
    // not answer is unreadable, not an account with no messages. `table_columns`
    // returned {} on a PRAGMA failure and `cols.is_empty()` below made a damaged
    // store indistinguishable from a clean absence (B8-039).
    let conn = match open_readonly(path) {
        Ok(conn) => conn,
        Err(e) => {
            return unreadable(
                case_id,
                parent_id,
                format!(
                    "the Instagram Direct database is named as evidence and would not open: {e}"
                ),
            )
        }
    };
    if let Err(why) = probe_catalogue(&conn) {
        return unreadable(case_id, parent_id, format!("the Instagram Direct database opened and its schema catalogue would not read, so whether it holds messages is undetermined rather than answered: {why}"));
    }
    // The catalogue read, so an absent table is a finding — but `direct.db`
    // is matched as Instagram's, and silence here renders exactly like an
    // account with no messages. Said, with the version seen.
    match probe_table(&conn, "messages") {
        Presence::Absent => {
            let obs = Observation {
                version: read_user_version(&conn),
                fields: None,
                required: MESSAGE_REQUIRED,
                recovered: 0,
            };
            return assess(&MESSAGE_SUPPORT, &obs, case_id, parent_id);
        }
        Presence::Undetermined(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the `messages` table could not be looked for: {why}"),
            )
        }
        Presence::Present => {}
    }
    let cols = match probe_columns(&conn, "messages") {
        Ok(cols) => cols,
        Err(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("`messages` is present and its column list would not read: {why}"),
            )
        }
    };
    let fields = FieldMap::resolve(&cols, MESSAGE_FIELDS);
    let version = read_user_version(&conn);
    let assessment = |recovered: usize| {
        let obs = Observation {
            version: version.clone(),
            fields: Some(&fields),
            required: MESSAGE_REQUIRED,
            recovered,
        };
        assess(&MESSAGE_SUPPORT, &obs, case_id, parent_id)
    };
    // A table carrying none of the fields that make a row a message is not
    // the one this parser knows; say so rather than manufacture rows from it.
    if MESSAGE_REQUIRED.iter().all(|f| fields.column(f).is_none()) {
        return assessment(0);
    }
    // Every `NULL` below stands for a logical field the map recorded as
    // unresolved and the assessment names.
    let col = |logical: &str| fields.column(logical).unwrap_or("NULL");
    let time_col = col("sent_at");
    let text_col = col("text");
    let user_col = col("account");
    let thread_col = col("thread");
    let msgjson_col = col("message_json");
    let type_col = col("message_type");
    let id_col = if cols.contains("message_id") {
        "message_id"
    } else {
        "rowid"
    };

    let sql = format!(
        "SELECT {id_col}, {time_col}, {text_col}, {user_col}, {thread_col}, \
                {msgjson_col}, {type_col} \
         FROM messages ORDER BY {time_col}"
    );
    // The table and its columns are established, so a statement that will not
    // prepare or run is a store this tool could not read — never an empty one
    // (HUNT-189).
    let query_failed = |e: rusqlite::Error| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            INCOMPLETE_TYPE,
            "messages",
            &e.to_string(),
        )];
        out.extend(assessment(0));
        out
    };
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(e) => return query_failed(e),
    };

    let rows = stmt.query_map([], |r| {
        Ok((
            col_text(r, 0),                             // _id / message_id
            r.get::<_, Option<i64>>(1).unwrap_or(None), // timestamp (µs)
            col_text(r, 2),                             // text
            col_text(r, 3),                             // user_id (owner)
            col_text(r, 4),                             // thread_id
            col_text(r, 5),                             // message json (stored as BLOB)
            col_text(r, 6),                             // message_type (text)
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
        let (msg_id, ts, text, owner, thread, msg_json, msg_type) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Instagram: skipping undecodable messages row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        let date = ts.and_then(unix_seconds_from_magnitude);
        let json_val: Option<Value> = msg_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());

        // Media messages carry no `text`; surface the URL from the JSON blob.
        let (body, media_url) = match (text, &json_val) {
            (Some(t), _) if !t.is_empty() => (Some(t), None),
            (_, Some(v)) => (None, media_url_from_value(v)),
            _ => (None, None),
        };

        // Direction is recorded per message as `is_sent_by_viewer`. Absent from
        // the JSON — or no JSON at all — means it was never recorded, and the
        // shared shell omits both `is_from_me` and `direction` rather than
        // writing a null a consumer could read as "received".
        let is_from_me = json_val
            .as_ref()
            .and_then(|v| v.get("is_sent_by_viewer"))
            .and_then(|v| v.as_bool());

        // A media message has no body, so the label falls back to the URL and
        // then to the message type. The derived label would say "(no text)"
        // and lose both.
        let preview = body
            .as_deref()
            .or(media_url.as_deref())
            .unwrap_or_else(|| msg_type.as_deref().unwrap_or("message"));
        let preview: String = preview.chars().take(60).collect();
        // A genuine `false` — this message had no attachment — is a finding and
        // is kept; only nulls are dropped by `extras`.
        let has_media = media_url.is_some();

        let msg = ChatMessage::new("Instagram", "Instagram Direct", "Android")
            .text(body)
            .date_secs(date)
            .from_me(is_from_me)
            // The thread is the conversation key the viewer groups on.
            .chat_identifier(thread.clone())
            .extras([
                ("source_table", json!("messages")),
                ("message_id", json!(msg_id)),
                ("account_user_id", json!(owner)),
                ("thread_id", json!(thread)),
                ("message_type", json!(msg_type)),
                ("media_url", json!(media_url)),
                ("has_attachments", json!(has_media)),
            ]);
        let name = format!("{}: {preview}", msg.direction().unwrap_or("message"));
        out.push(msg.display(name).into_artifact(case_id, parent_id));
    }
    // Counted before the marker joins the list, so the marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(case_id, parent_id, INCOMPLETE_TYPE, "messages", recovered));
    out.extend(assessment(recovered));
    out
}

/// Pull a media URL out of the message JSON value (media messages have no text).
fn media_url_from_value(v: &Value) -> Option<String> {
    for key in ["url", "media_url", "playable_url"] {
        if let Some(u) = v.get(key).and_then(|x| x.as_str()) {
            return Some(u.to_string());
        }
    }
    // Common nesting: {"media": {"url": ...}} or an image_versions2 candidate.
    v.get("media")
        .and_then(|m| {
            m.get("url").or_else(|| m.get("media_url")).or_else(|| {
                m.get("image_versions2")
                    .and_then(|iv| iv.get("candidates"))
                    .and_then(|c| c.get(0))
                    .and_then(|c0| c0.get("url"))
            })
        })
        .and_then(|u| u.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use seance_core::test_support::{DribbleSource, TruncatedSource};

    /// A source declaring twice the bytes it can deliver, over the shared double.
    ///
    /// The local copy this replaces bounds-checked in `usize` after casting the
    /// `u64` offset, which is lossless here and wrong on a 32-bit target; the
    /// shared one compares in `u64` space. `declared = 2 x len` keeps the exact
    /// shape every assertion below was written against.
    fn truncated(bytes: Vec<u8>) -> TruncatedSource {
        let declared = (bytes.len() as u64) * 2;
        TruncatedSource::new(bytes, declared)
    }
    use super::*;
    use rusqlite::Connection;
    use seance_sqlite_util::TempDb;
    use std::fs;

    /// Build a direct.db matching the REAL Android schema (verified against a
    /// Hickman Android-14 image: `_id`, `user_id`, `thread_id`, string
    /// `message_type`, direction inside the `message` JSON as
    /// `is_sent_by_viewer`, µs timestamps) and confirm recovery.
    #[test]
    fn parses_real_direct_schema() {
        let dir = std::env::temp_dir().join(format!("igtest_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("direct.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE threads(_id INTEGER, user_id TEXT, thread_id TEXT);
             CREATE TABLE messages(
               _id INTEGER, user_id TEXT, server_item_id TEXT, client_item_id TEXT,
               thread_id TEXT, recipient_ids TEXT, timestamp INTEGER,
               message_type TEXT, text TEXT, message TEXT);
             INSERT INTO messages VALUES
               (1,'100','s1','c1','t1','200', 1700000000000000, 'text',
                 'give it a go', '{\"item_type\":\"text\",\"is_sent_by_viewer\":true}'),
               (2,'100','s2','c2','t1','200', 1700000005000000, 'text',
                 'hello back', '{\"item_type\":\"text\",\"is_sent_by_viewer\":false}'),
               (3,'100','s3','c3','t1','200', 1700000009000000, 'media', NULL,
                 '{\"item_type\":\"media\",\"is_sent_by_viewer\":false,\"media\":{\"url\":\"https://cdn/x.jpg\"}}');",
        )
        .unwrap();
        drop(conn);

        let content = fs::read(&db).unwrap();
        let tmp = TempDb::write(&content, "instagram").unwrap();
        let out = parse_direct(tmp.path(), Uuid::new_v4(), Uuid::new_v4());
        let _ = fs::remove_dir_all(&dir);

        let out = messages(&out);
        assert_eq!(out.len(), 3);
        let m1 = &out[0].metadata;
        assert_eq!(m1["text"], "give it a go");
        assert_eq!(m1["date"], 1_700_000_000); // microseconds -> seconds
        assert_eq!(m1["is_from_me"], true); // is_sent_by_viewer
        assert_eq!(m1["message_type"], "text");
        assert_eq!(m1["chat_identifier"], "t1");
        let m2 = &out[1].metadata;
        assert_eq!(m2["is_from_me"], false);
        let m3 = &out[2].metadata;
        assert_eq!(m3["media_url"], "https://cdn/x.jpg");
        assert_eq!(m3["has_attachments"], true);
    }

    /// Regression: on real installs the `message` JSON is stored with BLOB
    /// affinity, not TEXT. Reading it as a `String` fails, which previously
    /// dropped the `message` JSON and left direction unknown. `col_text` must
    /// recover it from the raw bytes so `is_sent_by_viewer` is still read.
    #[test]
    fn reads_direction_from_blob_stored_message_json() {
        let dir = std::env::temp_dir().join(format!("igblob_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("direct.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages(
               _id INTEGER, user_id TEXT, thread_id TEXT,
               timestamp INTEGER, message_type TEXT, text TEXT, message BLOB);",
        )
        .unwrap();
        // Bind the JSON as raw bytes so the column takes BLOB affinity, exactly
        // as the real store does.
        conn.execute(
            "INSERT INTO messages VALUES (1,'100','t1',1700000000000000,'text','hey',?1)",
            rusqlite::params![br#"{"item_type":"text","is_sent_by_viewer":true}"#.to_vec()],
        )
        .unwrap();
        drop(conn);

        let content = fs::read(&db).unwrap();
        let tmp = TempDb::write(&content, "instagram").unwrap();
        let out = parse_direct(tmp.path(), Uuid::new_v4(), Uuid::new_v4());
        let _ = fs::remove_dir_all(&dir);

        let out = messages(&out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["is_from_me"], true);
        assert_eq!(out[0].metadata["text"], "hey");
    }

    /// An unset (0) timestamp is an absent key, never 1970-01-01: a fabricated
    /// epoch date is a false timeline anchor.
    #[test]
    fn zero_timestamp_is_absent_not_1970() {
        assert_eq!(unix_seconds_from_magnitude(0), None);
        assert_eq!(unix_seconds_from_magnitude(-5), None);
        assert_eq!(
            unix_seconds_from_magnitude(1_700_000_000_000_000),
            Some(1_700_000_000)
        );

        let dir = std::env::temp_dir().join(format!("igzero_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("direct.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages(
               _id INTEGER, user_id TEXT, thread_id TEXT,
               timestamp INTEGER, message_type TEXT, text TEXT, message TEXT);
             INSERT INTO messages VALUES (1,'100','t1',0,'text','undated',NULL);",
        )
        .unwrap();
        drop(conn);

        let content = fs::read(&db).unwrap();
        let tmp = TempDb::write(&content, "instagram").unwrap();
        let out = parse_direct(tmp.path(), Uuid::new_v4(), Uuid::new_v4());
        let _ = fs::remove_dir_all(&dir);

        let out = messages(&out);
        assert_eq!(out.len(), 1);
        assert!(
            out[0].metadata["date"].is_null(),
            "unset timestamp must be absent, not 1970"
        );
    }

    #[test]
    fn ignores_non_instagram_files() {
        assert!(is_instagram_db("direct.db"));
        assert!(is_instagram_db("com.instagram.android/databases/direct.db"));
        assert!(!is_instagram_db("cache4.db"));
        assert!(!is_instagram_db("msgstore.db"));
    }
    /// One-message Direct database, as bytes.
    fn direct_db_bytes() -> Vec<u8> {
        direct_db_bytes_with(0, "text")
    }

    /// One-message Direct database at `user_version`, with the body column
    /// under `text_col`. No real Instagram store is held, so 0 (SQLite's
    /// default) is the only version this fixture can honestly carry by default.
    fn direct_db_bytes_with(user_version: i64, text_col: &str) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("igshort_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("direct.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(&format!(
            "PRAGMA user_version = {user_version};
             CREATE TABLE messages(
               _id INTEGER, user_id TEXT, thread_id TEXT,
               timestamp INTEGER, message_type TEXT, {text_col} TEXT, message TEXT);
             INSERT INTO messages VALUES
               (1,'100','t1',1700000000000000,'text','only surviving dm',
                '{{\"item_type\":\"text\",\"is_sent_by_viewer\":true}}');"
        ))
        .unwrap();
        drop(conn);
        let bytes = fs::read(&db).unwrap();
        let _ = fs::remove_dir_all(&dir);
        bytes
    }

    fn schema_notes(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["warning_class"] == "ParserStaleWarning")
            .collect()
    }

    /// HUNT-189: `messages` found and its columns resolved, and a statement
    /// that would not prepare returned an empty list. The fixture is the real
    /// Android schema above with `timestamp` declared under Android's
    /// framework-only `LOCALIZED` collation, which the `ORDER BY` needs and
    /// stock SQLite does not have; SQLite will not CREATE such a table, so the
    /// catalogue is edited after the real rows go in.
    #[test]
    fn a_messages_query_that_will_not_run_is_reported_unreadable_not_empty() {
        let dir = std::env::temp_dir().join(format!("igq_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("direct.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE threads(_id INTEGER, user_id TEXT, thread_id TEXT);
             CREATE TABLE messages(
               _id INTEGER, user_id TEXT, server_item_id TEXT, client_item_id TEXT,
               thread_id TEXT, recipient_ids TEXT, timestamp INTEGER,
               message_type TEXT, text TEXT, message TEXT);
             INSERT INTO messages VALUES
               (1,'100','s1','c1','t1','200', 1700000000000000, 'text',
                 'give it a go', '{\"item_type\":\"text\",\"is_sent_by_viewer\":true}');
             PRAGMA writable_schema = ON;
             UPDATE sqlite_master SET sql = replace(sql, 'timestamp INTEGER', 'timestamp INTEGER COLLATE LOCALIZED')
               WHERE name = 'messages';
             PRAGMA writable_schema = OFF;",
        )
        .unwrap();
        drop(conn);
        let content = fs::read(&db).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let tmp = TempDb::write(&content, "instagram").unwrap();
        let out = parse_direct(tmp.path(), Uuid::new_v4(), Uuid::new_v4());
        assert!(messages(&out).is_empty());
        let v: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["status"] == json!("DatabaseUnreadable"))
            .collect();
        assert_eq!(v.len(), 1, "no DatabaseUnreadable record: {out:?}");
        assert_eq!(v[0].metadata["type"], json!(INCOMPLETE_TYPE));
        assert_eq!(v[0].metadata["source_table"], json!("messages"));
        assert!(v[0].metadata["sqlite_error"]
            .as_str()
            .unwrap()
            .contains("LOCALIZED"));
    }

    fn messages(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["subtype"] == "chat_message")
            .collect()
    }

    fn run_source(ds: std::sync::Arc<dyn seance_core::data_source::DataSource>) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "direct.db" }),
        );
        InstagramParser.process(&art).unwrap()
    }

    /// B2-124: the database was staged without comparing what came back against
    /// what the source declared, so a truncated thread store parsed as a
    /// complete one. What an examiner learns: whether the messages on screen
    /// are the whole thread or only the readable part of it.
    #[test]
    fn a_short_read_marks_every_record_it_produced() {
        let out = run_source(std::sync::Arc::new(truncated(direct_db_bytes())));
        let dm = out
            .iter()
            .find(|a| a.metadata.get("subtype").and_then(|v| v.as_str()) == Some("chat_message"))
            .expect("the readable prefix still parses");
        assert_eq!(dm.metadata["content_incomplete"], true);
        assert_eq!(dm.metadata["content_incomplete_reason"], "short_read");
        assert!(
            out.iter()
                .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                    == Some("DatabaseNotStagedInFull")),
            "a partial spill must be reported in its own right"
        );
    }

    /// The counterpart: a database read whole must stay unmarked, and a source
    /// that answers in small chunks is a whole database, not a non-SQLite file.
    #[test]
    fn a_chunked_but_complete_source_is_parsed_without_marks() {
        let out = run_source(std::sync::Arc::new(DribbleSource::new(
            direct_db_bytes(),
            4,
        )));
        let msgs = messages(&out);
        assert_eq!(msgs.len(), 1, "a chunked source is not a non-SQLite file");
        assert!(out
            .iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()));
    }

    /// ROADMAP §1.4a. No real Instagram `direct.db` is held by this project (the
    /// Hickman image the column set was once checked against is not on this
    /// machine, and no version was recorded from it), so this parser declares NO
    /// validated range — a range endpoint not read out of a real file would be
    /// a number copied from somewhere. It records the version it saw and says
    /// it was compared against nothing. There is no "out of range" test here;
    /// there cannot be.
    #[test]
    fn an_instagram_store_declares_no_validated_range_and_records_the_version_it_saw() {
        let out = run_source(std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(direct_db_bytes_with(31, "text")),
        ));
        let msgs = messages(&out);
        assert_eq!(msgs.len(), 1);
        seance_core::test_support::assert_no_incompleteness_stamps(msgs.iter().copied());

        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "{out:?}");
        let note = notes[0];
        assert_eq!(note.metadata["type"], "InstagramIncomplete");
        assert_eq!(note.metadata["status"], "SchemaNotRanged");
        assert_eq!(note.metadata["schema_version_seen"], 31);
        assert!(
            note.metadata.get("schema_version_supported").is_none(),
            "no range may be stated where none was validated: {note:?}"
        );
        assert!(note.metadata["schema_unranged_reason"]
            .as_str()
            .unwrap()
            .contains("no real"));
        assert!(note.metadata.get("content_incomplete").is_none());
        assert_eq!(note.metadata["subtype"], "parser_stale");
    }

    /// `PRAGMA user_version` 0 is SQLite's default, so it is the ABSENCE of a
    /// version — never a version older than anything.
    #[test]
    fn an_instagram_store_that_never_recorded_a_version_is_disclosed_as_unrecorded_not_older() {
        let out = run_source(std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(direct_db_bytes()),
        ));
        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "{out:?}");
        assert_eq!(notes[0].metadata["status"], "SchemaNotRanged");
        assert_eq!(notes[0].metadata["schema_version_not_recorded"], true);
        assert!(notes[0].metadata.get("schema_version_seen").is_none());
        assert!(!notes[0].metadata["detail"]
            .as_str()
            .unwrap()
            .contains("OLDER"));
    }

    /// Instagram churns this schema across app versions, and a renamed `text`
    /// column used to make every record silently text-less. What can be parsed
    /// still is, and the note names the LOGICAL field that went.
    #[test]
    fn an_instagram_store_that_renamed_the_body_column_claims_incompleteness_and_names_the_field() {
        let out = run_source(std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(direct_db_bytes_with(0, "body")),
        ));
        let msgs = messages(&out);
        assert_eq!(msgs.len(), 1, "what can be parsed still is: {out:?}");
        assert!(msgs[0].metadata.get("text").is_none());
        assert_eq!(msgs[0].metadata["is_from_me"], true);

        let note = schema_notes(&out)
            .into_iter()
            .find(|a| a.metadata["status"] == "SchemaFieldsUnresolved")
            .expect("the missing body column must be reported");
        assert_eq!(note.metadata["schema_unresolved_fields"], json!(["text"]));
        assert_eq!(note.metadata["content_incomplete"], true);
        assert_eq!(note.metadata["content_incomplete_reason"], "unvalidated");
        assert_eq!(note.metadata["inventory_incomplete"], true);
        assert_eq!(note.metadata["records_recovered"], 1);
        assert_eq!(note.metadata["subtype"], "parser_stale");
    }

    /// `direct.db` is matched as Instagram's. A readable catalogue with no
    /// `messages` table is either a schema this parser predates or not the
    /// Direct store — and silence would render exactly like an account with no
    /// messages.
    #[test]
    fn an_instagram_store_without_the_messages_table_is_not_silently_empty() {
        let dir = std::env::temp_dir().join(format!("ignotable_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("direct.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE threads(_id INTEGER, thread_id TEXT);")
            .unwrap();
        drop(conn);
        let bytes = fs::read(&db).unwrap();
        let _ = fs::remove_dir_all(&dir);

        let out = run_source(std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(bytes),
        ));
        assert!(messages(&out).is_empty());
        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "{out:?}");
        assert_eq!(notes[0].metadata["status"], "SchemaTableAbsent");
        assert_eq!(notes[0].metadata["table"], "messages");
        assert_eq!(notes[0].metadata["content_incomplete"], true);
        assert_eq!(
            notes[0].metadata["content_incomplete_reason"],
            "unvalidated"
        );
    }

    /// Bytes 103..105 are page 1's b-tree cell count; SQLite rejects a page
    /// whose cell count exceeds `(page_size - 8) / 6`, so the schema catalogue
    /// will not read while the file still opens.
    fn corrupt_the_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes[103] = 0xFF;
        bytes[104] = 0xFF;
        bytes
    }

    /// B8-039. `cols.is_empty()` turned an empty column set from a failed PRAGMA into the
    /// same silence a clean absence produces, so the parser returned
    /// nothing for a store it could not read. Nothing is exactly what a device
    /// that never had Instagram produces, so a damaged database was reported as an
    /// app that was never installed — an exculpatory finding nobody established.
    ///
    /// Against the unfixed code this returns an empty vector.
    #[test]
    fn a_corrupt_store_is_not_reported_as_a_device_without_the_app() {
        let out = run_source(std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(corrupt_the_catalogue(
                direct_db_bytes(),
            )),
        ));

        assert!(
            !out.is_empty(),
            "an unreadable Instagram store must not render as a device that never had Instagram"
        );
        let marker = out
            .iter()
            .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
            .expect("the store was identified and not examined; that must be stated");
        assert_eq!(marker.metadata["type"], json!("InstagramIncomplete"));
        assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    }
}
