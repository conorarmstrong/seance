#![forbid(unsafe_code)]
//! Snapchat parser (Android/iOS "Arroyo" chat store + `main.db` friends).
//!
//! [`SnapchatParser`] self-selects Snapchat's SQLite databases and emits
//! [`ParsedRecord`](ArtifactType::ParsedRecord)s:
//!
//! - **`arroyo.db`** (`conversation_message`) → one `chat_message` record per
//!   row: conversation id, sender id, creation/read timestamps (epoch **ms**),
//!   a content-type label, and read state. The same schema is used on iOS
//!   (`.../com.toyopagroup.picaboo/.../arroyo/arroyo.db`).
//! - **`main.db`** (`Friend`) → one `SnapchatContact` record per friend:
//!   username, user id, display name, added time.
//!
//! # The extraction ceiling (stated plainly)
//!
//! Snapchat is built to keep little on device. The message **body** lives inside
//! the `message_content` **protobuf** blob and is ephemeral by design (default
//! delete-after-view or 24h), so for most rows there is **no recoverable text** —
//! what survives is the conversation metadata (who, when, type, read state) and
//! the friends list. A best-effort printable-string sweep of the protobuf
//! recovers text where it is still present; otherwise `text` is null and the
//! record stands as an activity/metadata artifact. Nothing here panics on a
//! non-Snapchat file, a missing table, or a corrupt row.

use rusqlite::Connection;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    artifact_name, open_readonly, probe_catalogue, probe_columns, probe_table, query_failed_marker,
    stage_sqlite_db, table_columns, unreadable_store_marker, ChatMessage, FieldMap, Presence,
    RowDrops, SqliteEntry, SupportedRange, MAX_DB_BYTES,
};
use serde_json::json;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

pub mod schema;
use schema::{
    assess, read_user_version, Observation, SchemaSupport, SupportBound, USER_VERSION_LOCATOR,
};

pub struct SnapchatParser;

/// The record type every Arroyo incompleteness marker and schema note is filed
/// under. Never `"Snapchat"`: `seance_db` groups conversations by
/// `metadata.$.type`, and a marker carrying the message type would render as a
/// phantom one-message conversation.
const INCOMPLETE_TYPE: &str = "SnapchatIncomplete";

/// The same for the friends list.
const CONTACT_INCOMPLETE_TYPE: &str = "SnapchatContactIncomplete";

/// Every logical field read from `conversation_message`, with the physical
/// column(s) that have carried it. Both real stores on file carry exactly this
/// set; a rename is absorbed by adding a candidate here, not by a code path.
const ARROYO_FIELDS: &[(&str, &[&str])] = &[
    ("conversation", &["client_conversation_id"]),
    ("server_message_id", &["server_message_id"]),
    ("sender", &["sender_id"]),
    ("sent_at", &["creation_timestamp"]),
    ("read_at", &["read_timestamp"]),
    ("content_type", &["content_type"]),
    ("content", &["message_content"]),
];

/// Without these a `conversation_message` row is not a message record: who,
/// in which conversation, when. The body is NOT required — it is gone by
/// design on most rows, and its column being absent is a different fact from
/// its content being absent.
const ARROYO_REQUIRED: &[&str] = &["conversation", "sender", "sent_at"];

/// The validated range is a single point because both real stores read 102 —
/// not because a wider range is known. A modern store past it is disclosed,
/// not claimed incomplete (see `schema`).
const ARROYO_SUPPORT: SchemaSupport = SchemaSupport {
    app: "snapchat-arroyo",
    store: "arroyo.db",
    table: "conversation_message",
    record_type: INCOMPLETE_TYPE,
    locator: USER_VERSION_LOCATOR,
    bound: SupportBound::Validated {
        range: SupportedRange {
            min: 102,
            max: Some(102),
        },
        evidence: "user_version 102 read from two real stores: the Magnet Virtual Summit 2022 \
                   Android CTF image (Pixel 3) member \
                   data/data/com.snapchat.android/databases/arroyo.db (2022-02-13, 7 rows) and \
                   the Magnet User Summit 2022 iOS CTF (iPhone 8) full-file-system member \
                   /private/var/mobile/Containers/Data/Application/55937BA7-D5B0-48A7-9FCF-CBBB350952A1/Documents/user_scoped/ba07af6c6efbca061e805f6b36c216872a4fce21e0f73e6a594014e82590a5ea/arroyo/arroyo.db \
                   (2022-01-30, 2 rows); a single-point range because both read 102",
    },
};

/// Every logical field read from `Friend`. `username` is also the signature
/// that makes a generically-named `main.db` Snapchat's, so it is checked
/// before this map is built.
const FRIEND_FIELDS: &[(&str, &[&str])] = &[
    ("username", &["username"]),
    ("user_id", &["userId"]),
    ("display_name", &["displayName"]),
    ("added_at", &["addedTimestamp"]),
];

const FRIEND_REQUIRED: &[&str] = &["username"];

/// One real `main.db` on file, so one point.
const FRIEND_SUPPORT: SchemaSupport = SchemaSupport {
    app: "snapchat-friends",
    store: "main.db",
    table: "Friend",
    record_type: CONTACT_INCOMPLETE_TYPE,
    locator: USER_VERSION_LOCATOR,
    bound: SupportBound::Validated {
        range: SupportedRange {
            min: 427,
            max: Some(427),
        },
        evidence: "user_version 427 read from one real store: the Magnet Virtual Summit 2022 \
                   Android CTF image (Pixel 3) member \
                   data/data/com.snapchat.android/databases/main.db with its -wal (2022-02-13, \
                   3 Friend rows); a single-point range because one file was seen",
    },
};

impl ForensicsModule for SnapchatParser {
    fn id(&self) -> &str {
        "plugin.messaging.snapchat"
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
        let base = name.to_ascii_lowercase();
        let base = base.rsplit('/').next().unwrap_or("");
        let kind = match base {
            "arroyo.db" => Kind::Arroyo,
            "main.db" => Kind::Main,
            _ => return Ok(Vec::new()),
        };

        debug!("SnapchatParser inspecting {name}");
        // The shared gate skips directories and artifacts with no reachable
        // content, and probes the magic BEFORE staging so a non-SQLite file
        // named main.db is not spilled at all. The probe LOOPS over short
        // reads: a windowed / container-backed source is entitled to return
        // fewer bytes than asked for, and a single `read_at` that came back
        // with 8 bytes would file a real arroyo.db as "not a database" and drop
        // the whole chat store. Staging also records whether the database was
        // taken in full — an arroyo.db over the byte cap, or one whose source
        // stops early, still opens and answers queries, and on Snapchat, where
        // most bodies are already gone by design, an undersold message list is
        // especially easy to mistake for the ceiling.
        let temp = match stage_sqlite_db(artifact, "snapchat", MAX_DB_BYTES) {
            SqliteEntry::Staged(temp) => temp,
            // `arroyo.db` names Snapchat and nothing else, and the header
            // matched, so this is a Snapchat store this tool identified and did
            // not examine — on an app where most bodies are already gone by
            // design, an empty list is especially easy to read as "there was
            // nothing here". `main.db` gets NO such record: dozens of unrelated
            // apps use that name, this parser does not know the file is
            // Snapchat's until it finds the `Friend` table, and a marker
            // emitted first would assert a Snapchat store on the strength of a
            // generic filename.
            SqliteEntry::StagingFailed(e) if matches!(kind, Kind::Arroyo) => {
                return Ok(vec![unreadable_store_marker(
                    artifact.case_id,
                    artifact.id,
                    INCOMPLETE_TYPE,
                    format!("the Snapchat database `{name}` carried the SQLite header and could not be staged for examination: {e}"),
                )])
            }
            _ => return Ok(Vec::new()),
        };
        let platform = detect_platform(artifact);
        let mut out = match kind {
            Kind::Arroyo => parse_arroyo(temp.path(), artifact.case_id, artifact.id, platform),
            // main.db is a common filename; only treat it as Snapchat's when it
            // actually has the Friend table, so we don't hijack another app's db.
            Kind::Main => parse_main_friends(temp.path(), artifact.case_id, artifact.id, platform),
        };
        // `main.db` is a common filename, so a database that yielded nothing is
        // usually another app's and not ours to comment on — unless the file
        // itself could not be staged whole, which is worth saying either way.
        if !out.is_empty() || temp.content_incomplete_reason().is_some() {
            temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        }
        Ok(out)
    }
}

enum Kind {
    Arroyo,
    Main,
}

/// Best-effort platform attribution from the artifact's path metadata. Snapchat
/// uses the same Arroyo/`main.db` schema on Android and iOS, so the platform is
/// inferred from where the database lived rather than hardcoded. Returns
/// `"Unknown"` when neither family's markers are present, so iOS evidence is
/// never fabricated as Android.
fn detect_platform(artifact: &Artifact) -> &'static str {
    let mut hay = String::new();
    for key in ["name", "path", "parent_path", "container_path"] {
        if let Some(s) = artifact.metadata.get(key).and_then(|v| v.as_str()) {
            hay.push_str(s);
            hay.push('\n');
        }
    }
    let hay = hay.to_ascii_lowercase();
    if hay.contains("com.toyopagroup.picaboo")
        || hay.contains("toyopagroup")
        || hay.contains("picaboo")
        || hay.contains("/var/mobile")
    {
        "iOS"
    } else if hay.contains("com.snapchat.android")
        || hay.contains("/data/data")
        || hay.contains("/data/user")
    {
        "Android"
    } else {
        "Unknown"
    }
}

fn open_ro(path: &Path) -> Option<Connection> {
    open_readonly(path).ok()
}

/// Snapchat's Arroyo `content_type` enum → a human label. Unknown values keep
/// their integer so nothing is silently mislabelled.
fn content_label(ct: Option<i64>) -> String {
    match ct {
        Some(0) => "unknown".into(),
        Some(1) => "text".into(),
        Some(2) => "snap".into(),
        Some(3) => "media".into(),
        Some(5) => "status".into(),
        Some(6) => "reaction".into(),
        Some(n) => format!("type {n}"),
        None => "unknown".into(),
    }
}

/// Best-effort recovery of a text body from the `message_content` protobuf via
/// the shared [`recover_protobuf_text`](seance_core::blob_text::recover_protobuf_text)
/// helper: it reads exact protobuf field boundaries, so the message text comes
/// out with correct UTF-8 and no framing bytes, and an ephemeral/encrypted blob
/// with no clean text field yields `None` rather than binary noise.
fn text_from_protobuf(blob: &[u8]) -> Option<String> {
    seance_core::blob_text::recover_protobuf_text(blob)
}

/// The record that says a Snapchat store was identified and could not be read.
/// Zero artifacts would render identically to a device that never had Snapchat.
fn unreadable(case_id: Uuid, parent_id: Uuid, detail: String) -> Vec<Artifact> {
    vec![unreadable_store_marker(
        case_id,
        parent_id,
        INCOMPLETE_TYPE,
        detail,
    )]
}

fn parse_arroyo(path: &Path, case_id: Uuid, parent_id: Uuid, platform: &str) -> Vec<Artifact> {
    // Named as Snapchat evidence, so a store that will not open or will not
    // answer is unreadable, not a device without Snapchat. `table_columns`
    // returned {} on a PRAGMA failure and `cols.is_empty()` below turned that
    // into the same silence a clean absence produces (B8-039).
    let Some(conn) = open_ro(path) else {
        return unreadable(
            case_id,
            parent_id,
            "the Snapchat database is named as evidence and would not open".to_string(),
        );
    };
    if let Err(why) = probe_catalogue(&conn) {
        return unreadable(case_id, parent_id, format!("the Snapchat database opened and its schema catalogue would not read, so whether it holds messages is undetermined rather than answered: {why}"));
    }
    // The catalogue read, so an absent table is a finding — but `arroyo.db`
    // names Snapchat and nothing else, and silence here renders exactly like
    // a device with no Snapchat messages. Said, with the version seen.
    match probe_table(&conn, "conversation_message") {
        Presence::Absent => {
            let obs = Observation {
                version: read_user_version(&conn),
                fields: None,
                required: ARROYO_REQUIRED,
                recovered: 0,
            };
            return assess(&ARROYO_SUPPORT, &obs, case_id, parent_id);
        }
        Presence::Undetermined(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the `conversation_message` table could not be looked for: {why}"),
            )
        }
        Presence::Present => {}
    }
    let cols = match probe_columns(&conn, "conversation_message") {
        Ok(cols) => cols,
        Err(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!(
                    "`conversation_message` is present and its column list would not read: {why}"
                ),
            )
        }
    };
    let fields = FieldMap::resolve(&cols, ARROYO_FIELDS);
    let version = read_user_version(&conn);
    let assessment = |recovered: usize| {
        let obs = Observation {
            version: version.clone(),
            fields: Some(&fields),
            required: ARROYO_REQUIRED,
            recovered,
        };
        assess(&ARROYO_SUPPORT, &obs, case_id, parent_id)
    };
    // A table carrying none of the fields that make a row a message is not
    // the table this parser knows; the assessment says so, and no row is
    // manufactured out of it.
    if ARROYO_REQUIRED.iter().all(|f| fields.column(f).is_none()) {
        return assessment(0);
    }
    // Every `NULL` below stands for a logical field the map recorded as
    // unresolved, so the assessment names it; that is what keeps a renamed
    // column from becoming a silent empty field.
    let col = |logical: &str| fields.column(logical).unwrap_or("NULL");
    let convo = col("conversation");
    let srvid = col("server_message_id");
    let sender = col("sender");
    let sent_at = col("sent_at");
    let read_ts = col("read_at");
    let ctype = col("content_type");
    let content = col("content");

    let sql = format!(
        "SELECT {convo}, {srvid}, {sender}, {sent_at}, {read_ts}, {ctype}, {content} \
         FROM conversation_message ORDER BY {convo}, {sent_at}"
    );
    // The table and its columns are established, so a statement that will not
    // prepare or run is a store this tool could not read — never an empty one
    // (HUNT-189).
    let query_failed = |e: rusqlite::Error| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            INCOMPLETE_TYPE,
            "conversation_message",
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
            r.get::<_, Option<String>>(0).unwrap_or(None),
            r.get::<_, Option<i64>>(1).unwrap_or(None),
            r.get::<_, Option<String>>(2).unwrap_or(None),
            r.get::<_, Option<i64>>(3).unwrap_or(None),
            r.get::<_, Option<i64>>(4).unwrap_or(None),
            r.get::<_, Option<i64>>(5).unwrap_or(None),
            r.get::<_, Option<Vec<u8>>>(6).unwrap_or(None),
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
        let (convo_id, server_id, sender_id, created_ms, read_ms, ct, content_blob) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    "Snapchat: skipping undecodable conversation_message row: {}",
                    e
                );
                drops.record(&e);
                continue;
            }
        };
        // A zero/unset creation timestamp is an absent key, not 1970-01-01:
        // fabricating one would anchor the message on the timeline at the epoch.
        let date = created_ms.filter(|&v| v > 0).map(|ms| ms / 1000);
        // `read_timestamp` is epoch **milliseconds** on disk, like
        // `creation_timestamp`. Normalize it to seconds so a consumer treating
        // both fields as Unix seconds does not place the read time ~1000x in the
        // future. A zero/unset value is dropped rather than surfaced as 1970.
        let read_date = read_ms.filter(|&v| v > 0).map(|ms| ms / 1000);
        let label = content_label(ct);
        let text = content_blob
            .as_deref()
            .and_then(text_from_protobuf)
            .filter(|_| label == "text" || label.starts_with("type"));
        let read = read_ms.map(|v| v > 0);

        let preview = text
            .as_deref()
            .map(|t| t.chars().take(60).collect::<String>())
            .unwrap_or_else(|| format!("[{label}]"));

        // Bodies are ephemeral; make the ceiling explicit on the record. This
        // is a genuine `false` when nothing was recovered, not an absent fact,
        // so it survives the shell's null-dropping.
        let body_recovered = text.is_some();
        // The content type is what distinguishes one snap from the next when no
        // body survived, so it leads the label rather than the derived
        // direction-first form.
        let display = format!("snap {label}: {preview}");
        // `arroyo.db` records no direction at all: there is no owner-account
        // column to compare `sender_id` against, so `is_from_me`/`direction`
        // are left off rather than inferred.
        out.push(
            ChatMessage::new("Snapchat", "Snapchat", platform)
                .text(text)
                .date_secs(date)
                .chat_identifier(convo_id.clone())
                .extras([
                    ("source_table", json!("conversation_message")),
                    ("server_message_id", json!(server_id)),
                    ("conversation_id", json!(convo_id)),
                    ("sender_id", json!(sender_id)),
                    ("read_timestamp", json!(read_date)),
                    ("read", json!(read)),
                    ("content_type", json!(label)),
                    ("body_recovered", json!(body_recovered)),
                ])
                .display(display)
                .into_artifact(case_id, parent_id),
        );
    }
    // Counted before the marker joins the list, so the marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        INCOMPLETE_TYPE,
        "conversation_message",
        recovered,
    ));
    out.extend(assessment(recovered));
    out
}

fn parse_main_friends(
    path: &Path,
    case_id: Uuid,
    parent_id: Uuid,
    platform: &str,
) -> Vec<Artifact> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let cols = table_columns(&conn, "Friend");
    // Only Snapchat's main.db has a Friend table with a username — this keeps us
    // from claiming an unrelated app's main.db. The schema assessment comes
    // AFTER this gate for the same reason: a note on a foreign `main.db`
    // would assert a Snapchat store on the strength of a generic filename.
    if cols.is_empty() || !cols.contains("username") {
        return Vec::new();
    }
    let fields = FieldMap::resolve(&cols, FRIEND_FIELDS);
    let version = read_user_version(&conn);
    let assessment = |recovered: usize| {
        let obs = Observation {
            version: version.clone(),
            fields: Some(&fields),
            required: FRIEND_REQUIRED,
            recovered,
        };
        assess(&FRIEND_SUPPORT, &obs, case_id, parent_id)
    };
    // Each `NULL` is a field the map recorded as unresolved and the
    // assessment names.
    let col = |logical: &str| fields.column(logical).unwrap_or("NULL");
    let uid = col("user_id");
    let disp = col("display_name");
    let added = col("added_at");

    let sql = format!("SELECT username, {uid}, {disp}, {added} FROM Friend");
    // `Friend` with a `username` is what made this Snapchat's `main.db`, so a
    // statement that will not prepare or run is a friend list this tool could
    // not read — never an empty one (HUNT-189).
    let query_failed = |e: rusqlite::Error| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            CONTACT_INCOMPLETE_TYPE,
            "Friend",
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
            r.get::<_, Option<String>>(0).unwrap_or(None),
            r.get::<_, Option<String>>(1).unwrap_or(None),
            r.get::<_, Option<String>>(2).unwrap_or(None),
            r.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => return query_failed(e),
    };

    let mut out = Vec::new();
    // Same tally for the contact inventory: a dropped Friend row is an identity
    // this device knew and the case no longer shows (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (username, user_id, display, added_ms) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Snapchat: skipping undecodable Friend row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        // Unset "added" time stays absent rather than becoming 1970-01-01.
        let added_date = added_ms.filter(|&v| v > 0).map(|ms| ms / 1000);
        let metadata = json!({
            "type": "SnapchatContact",
            "subtype": "contact",
            "platform": platform,
            "source_table": "Friend",
            "service": "Snapchat",
            "username": username,
            "user_id": user_id,
            "display_name": display,
            "added_date": added_date,
            "name": display.clone().or(username.clone()).unwrap_or_default(),
        });
        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(parent_id)
                .with_subtype("contact"),
        );
    }
    // Counted before the marker joins the list, so the marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        CONTACT_INCOMPLETE_TYPE,
        "Friend",
        recovered,
    ));
    out.extend(assessment(recovered));
    out
}

#[cfg(test)]
mod tests {
    use seance_core::test_support::TruncatedSource;

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
    use seance_core::data_source::DataSource;
    use seance_sqlite_util::TempDb;
    use std::fs;

    #[test]
    fn parses_arroyo_metadata_and_friends() {
        let dir = std::env::temp_dir().join(format!("snaptest_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        // arroyo.db
        let arroyo = dir.join("arroyo.db");
        let c = Connection::open(&arroyo).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 102;
             CREATE TABLE conversation_message(
               client_conversation_id TEXT, client_message_id INTEGER,
               server_message_id INTEGER, sender_id TEXT,
               creation_timestamp INTEGER, read_timestamp INTEGER,
               content_type INTEGER, message_content BLOB);
             INSERT INTO conversation_message VALUES
               ('conv1', 1, 11, 'userA', 1721000000000, 1721000005000, 1,
                 x'0a0568656c6c6f'),
               ('conv1', 2, 12, 'userB', 1721000010000, 0, 2, x'00');",
        )
        .unwrap();
        drop(c);
        let content = fs::read(&arroyo).unwrap();
        let tmp = TempDb::write(&content, "snapchat").unwrap();
        let msgs = parse_arroyo(tmp.path(), Uuid::new_v4(), Uuid::new_v4(), "Android");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].metadata["date"], 1_721_000_000); // ms -> s
        assert_eq!(msgs[0].metadata["content_type"], "text");
        assert_eq!(msgs[0].metadata["text"], "hello"); // recovered from protobuf
        assert_eq!(msgs[0].metadata["read"], true);
        // read_timestamp is normalized to seconds, matching `date` (was raw ms).
        assert_eq!(msgs[0].metadata["read_timestamp"], 1_721_000_005);
        // An unread message (read_timestamp 0) drops the field rather than 1970.
        assert!(msgs[1].metadata["read_timestamp"].is_null());
        assert_eq!(msgs[1].metadata["content_type"], "snap");
        assert_eq!(msgs[1].metadata["body_recovered"], false);

        // main.db
        let main = dir.join("main.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 427;
             CREATE TABLE Friend(username TEXT, userId TEXT, displayName TEXT, addedTimestamp INTEGER);
             INSERT INTO Friend VALUES ('thisisdfir','uid1','DFIR Guy',1721500000000);",
        )
        .unwrap();
        drop(c);
        let content = fs::read(&main).unwrap();
        let tmp = TempDb::write(&content, "snapchat").unwrap();
        let friends = parse_main_friends(tmp.path(), Uuid::new_v4(), Uuid::new_v4(), "iOS");
        assert_eq!(friends.len(), 1);
        assert_eq!(friends[0].metadata["username"], "thisisdfir");
        assert_eq!(friends[0].metadata["display_name"], "DFIR Guy");
        assert_eq!(friends[0].metadata["added_date"], 1_721_500_000);
        // Platform is threaded through, not hardcoded.
        assert_eq!(friends[0].metadata["platform"], "iOS");

        let _ = fs::remove_dir_all(&dir);
    }

    /// An unset (0) timestamp is an absent key on every date field, never
    /// 1970-01-01 — a fabricated epoch date is a false timeline anchor.
    #[test]
    fn zero_timestamps_are_absent_not_1970() {
        let dir = std::env::temp_dir().join(format!("snapzero_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let arroyo = dir.join("arroyo.db");
        let c = Connection::open(&arroyo).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 102;
             CREATE TABLE conversation_message(
               client_conversation_id TEXT, server_message_id INTEGER, sender_id TEXT,
               creation_timestamp INTEGER, read_timestamp INTEGER,
               content_type INTEGER, message_content BLOB);
             INSERT INTO conversation_message VALUES
               ('conv1', 11, 'userA', 0, 0, 1, x'0a0568656c6c6f');",
        )
        .unwrap();
        drop(c);
        let content = fs::read(&arroyo).unwrap();
        let tmp = TempDb::write(&content, "snapchat").unwrap();
        let msgs = parse_arroyo(tmp.path(), Uuid::new_v4(), Uuid::new_v4(), "Android");
        assert_eq!(msgs.len(), 1);
        assert!(
            msgs[0].metadata["date"].is_null(),
            "unset creation_timestamp must be absent, not 1970"
        );

        let main = dir.join("main.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 427;
             CREATE TABLE Friend(username TEXT, userId TEXT, displayName TEXT, addedTimestamp INTEGER);
             INSERT INTO Friend VALUES ('nodate','uid2','No Date',0);",
        )
        .unwrap();
        drop(c);
        let content = fs::read(&main).unwrap();
        let tmp = TempDb::write(&content, "snapchat").unwrap();
        let friends = parse_main_friends(tmp.path(), Uuid::new_v4(), Uuid::new_v4(), "Android");
        assert_eq!(friends.len(), 1);
        assert!(
            friends[0].metadata["added_date"].is_null(),
            "unset addedTimestamp must be absent, not 1970"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn platform_inferred_from_path_not_hardcoded() {
        let ios = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({
                "name": "arroyo.db",
                "path": "/private/var/mobile/Containers/Data/Application/X/Documents/user_scoped/Y/com.toyopagroup.picaboo/arroyo/arroyo.db",
            }),
        );
        assert_eq!(detect_platform(&ios), "iOS");

        let android = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({
                "name": "arroyo.db",
                "path": "/data/data/com.snapchat.android/databases/arroyo.db",
            }),
        );
        assert_eq!(detect_platform(&android), "Android");

        // No markers → Unknown (never fabricated as Android).
        let bare = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "arroyo.db" }),
        );
        assert_eq!(detect_platform(&bare), "Unknown");
    }
    fn arroyo_bytes() -> Vec<u8> {
        arroyo_bytes_with(102, "sender_id")
    }

    /// One-message arroyo.db at `user_version`, with the sender column under
    /// `sender_col`. 102 and `sender_id` are what the two real stores carry.
    fn arroyo_bytes_with(user_version: i64, sender_col: &str) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("snapshort_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let arroyo = dir.join("arroyo.db");
        let c = Connection::open(&arroyo).unwrap();
        c.execute_batch(&format!(
            "PRAGMA user_version = {user_version};
             CREATE TABLE conversation_message(
               client_conversation_id TEXT, server_message_id INTEGER, {sender_col} TEXT,
               creation_timestamp INTEGER, read_timestamp INTEGER,
               content_type INTEGER, message_content BLOB);
             INSERT INTO conversation_message VALUES
               ('conv1', 11, 'userA', 1721000000000, 0, 1, x'0a0568656c6c6f');"
        ))
        .unwrap();
        drop(c);
        let bytes = fs::read(&arroyo).unwrap();
        let _ = fs::remove_dir_all(&dir);
        bytes
    }

    /// The `DatabaseUnreadable` records of type `ty` in `out`.
    fn query_unreadable<'a>(out: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
        out.iter()
            .filter(|a| a.metadata["status"] == json!("DatabaseUnreadable"))
            .filter(|a| a.metadata["type"] == json!(ty))
            .collect()
    }

    /// HUNT-189: `conversation_message` found and its columns resolved, and a
    /// statement that would not prepare returned an empty list. Here
    /// `creation_timestamp` is declared with Android's framework-only
    /// `LOCALIZED` collation, which the `ORDER BY` needs and stock SQLite does
    /// not have; SQLite will not CREATE such a table, so the catalogue is
    /// edited after the real rows go in.
    #[test]
    fn a_conversation_message_query_that_will_not_run_is_reported_unreadable_not_empty() {
        let dir = std::env::temp_dir().join(format!("snapq_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let arroyo = dir.join("arroyo.db");
        let c = Connection::open(&arroyo).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 102;
             CREATE TABLE conversation_message(
               client_conversation_id TEXT, server_message_id INTEGER, sender_id TEXT,
               creation_timestamp INTEGER, read_timestamp INTEGER,
               content_type INTEGER, message_content BLOB);
             INSERT INTO conversation_message VALUES
               ('conv1', 11, 'userA', 1721000000000, 0, 1, x'0a0568656c6c6f');
             PRAGMA writable_schema = ON;
             UPDATE sqlite_master
               SET sql = replace(sql, 'creation_timestamp INTEGER', 'creation_timestamp INTEGER COLLATE LOCALIZED')
               WHERE name = 'conversation_message';
             PRAGMA writable_schema = OFF;",
        )
        .unwrap();
        drop(c);
        let bytes = fs::read(&arroyo).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let out = run_arroyo(bytes);
        assert!(!out.iter().any(|a| a.metadata["type"] == json!("Snapchat")));
        let v = query_unreadable(&out, INCOMPLETE_TYPE);
        assert_eq!(v.len(), 1, "no DatabaseUnreadable record: {out:?}");
        assert_eq!(v[0].metadata["source_table"], json!("conversation_message"));
        assert!(v[0].metadata["sqlite_error"]
            .as_str()
            .unwrap()
            .contains("LOCALIZED"));
    }

    /// HUNT-189: a `main.db` whose `Friend` carries `username` (the gate that
    /// makes it Snapchat's) and whose query will not run — here `Friend` is a
    /// view sorting under the framework-only collation — returned an empty
    /// list, a device with no Snapchat friends.
    #[test]
    fn a_friend_query_that_will_not_run_is_reported_unreadable_not_empty() {
        let dir = std::env::temp_dir().join(format!("snapf_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("main.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(
            "CREATE TABLE friend_store(username TEXT, userId TEXT, displayName TEXT, addedTimestamp INTEGER);
             INSERT INTO friend_store VALUES ('thisisdfir','uid1','DFIR Guy',1721500000000);
             CREATE VIEW Friend AS SELECT username, userId, displayName, addedTimestamp
               FROM friend_store ORDER BY username COLLATE LOCALIZED;",
        )
        .unwrap();
        drop(c);
        let bytes = fs::read(&main).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let tmp = TempDb::write(&bytes, "snapchat").unwrap();
        let out = parse_main_friends(tmp.path(), Uuid::new_v4(), Uuid::new_v4(), "Android");
        assert!(!out
            .iter()
            .any(|a| a.metadata["type"] == json!("SnapchatContact")));
        let v = query_unreadable(&out, CONTACT_INCOMPLETE_TYPE);
        assert_eq!(v.len(), 1, "no DatabaseUnreadable record: {out:?}");
        assert_eq!(v[0].metadata["source_table"], json!("Friend"));
    }

    fn run_arroyo(bytes: Vec<u8>) -> Vec<Artifact> {
        let ds: std::sync::Arc<dyn DataSource> =
            std::sync::Arc::new(seance_core::data_source::ByteSliceDataSource::new(bytes));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "arroyo.db" }),
        );
        SnapchatParser.process(&art).unwrap()
    }

    fn schema_notes(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["warning_class"] == "ParserStaleWarning")
            .collect()
    }

    fn messages(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["subtype"] == "chat_message")
            .collect()
    }

    /// ROADMAP §1.4a. The validated range is 102..=102 because 102 is what
    /// BOTH real arroyo.db stores on file read (Android, 2022-02-13; iOS,
    /// 2022-01-30). A store past it is disclosed with the version seen and the
    /// range, and is still parsed: every column this parser reads resolved, so
    /// nothing is claimed incomplete — an incompleteness stamp on every modern
    /// Snapchat store would be a classifier firing on a non-finding.
    #[test]
    fn an_arroyo_newer_than_the_validated_range_is_disclosed_and_still_parsed() {
        let out = run_arroyo(arroyo_bytes_with(300, "sender_id"));

        let msgs = messages(&out);
        assert_eq!(
            msgs.len(),
            1,
            "the store past the range still parses: {out:?}"
        );
        seance_core::test_support::assert_no_incompleteness_stamps(msgs.iter().copied());

        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "one disclosure per store: {out:?}");
        let note = notes[0];
        assert_eq!(note.metadata["type"], "SnapchatIncomplete");
        assert_eq!(note.metadata["status"], "SchemaOutsideValidated");
        assert_eq!(note.metadata["schema_version_seen"], 300);
        assert_eq!(note.metadata["schema_version_supported"], "102..=102");
        assert!(
            note.metadata["schema_version_evidence"]
                .as_str()
                .unwrap()
                .contains("arroyo.db"),
            "the range must name the file each endpoint was read from"
        );
        assert!(note.metadata["detail"].as_str().unwrap().contains("NEWER"));
        assert!(
            note.metadata.get("content_incomplete").is_none(),
            "a version past the range is a disclosure, not an incompleteness claim: {note:?}"
        );
    }

    /// The positive anchor: at the validated version with every field
    /// resolving, the parse carries no schema note at all. A note present on
    /// every store would tell an examiner nothing.
    #[test]
    fn an_arroyo_at_the_validated_version_carries_no_schema_note() {
        let out = run_arroyo(arroyo_bytes_with(102, "sender_id"));
        assert_eq!(messages(&out).len(), 1);
        assert!(schema_notes(&out).is_empty(), "{out:?}");
    }

    /// A column rename is the edit that turns a working parser into a silent
    /// one: before this, `sender_id` going missing made every record
    /// sender-less with nothing on the case saying so. The record must name the
    /// LOGICAL field — the examiner needs to know the sender is missing, not
    /// which column list was tried.
    #[test]
    fn an_arroyo_that_renamed_a_required_column_claims_incompleteness_and_names_the_field() {
        let out = run_arroyo(arroyo_bytes_with(102, "from_user"));

        let msgs = messages(&out);
        assert_eq!(msgs.len(), 1, "what can be parsed still is: {out:?}");
        assert!(msgs[0].metadata.get("sender_id").is_none());

        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "{out:?}");
        let note = notes[0];
        assert_eq!(note.metadata["status"], "SchemaFieldsUnresolved");
        assert_eq!(note.metadata["schema_unresolved_fields"], json!(["sender"]));
        assert_eq!(note.metadata["content_incomplete"], true);
        assert_eq!(note.metadata["content_incomplete_reason"], "unvalidated");
        assert_eq!(note.metadata["inventory_incomplete"], true);
        assert_eq!(note.metadata["records_recovered"], 1);
        assert!(note.metadata["detail"].as_str().unwrap().contains("sender"));
        assert_eq!(note.metadata["subtype"], "parser_stale");
    }

    /// `PRAGMA user_version` is 0 on any store that never set one — SQLite's
    /// default — so 0 is the ABSENCE of a version, never a version older than
    /// the range. Both real arroyo stores set it; a store that does not is
    /// disclosed as unrecorded and compared against nothing.
    #[test]
    fn an_arroyo_that_never_recorded_a_version_is_not_called_older_than_the_range() {
        let out = run_arroyo(arroyo_bytes_with(0, "sender_id"));
        assert_eq!(messages(&out).len(), 1);
        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "{out:?}");
        let note = notes[0];
        assert_eq!(note.metadata["status"], "SchemaVersionNotRecorded");
        assert!(note.metadata.get("schema_version_seen").is_none());
        assert!(!note.metadata["detail"].as_str().unwrap().contains("OLDER"));
        assert!(note.metadata.get("content_incomplete").is_none());
    }

    /// `arroyo.db` names Snapchat and nothing else. A readable catalogue with
    /// no `conversation_message` table is either a schema this parser
    /// predates or not the chat store — and silence would render exactly like
    /// a device with no Snapchat messages.
    #[test]
    fn an_arroyo_without_the_message_table_is_not_silently_empty() {
        let dir = std::env::temp_dir().join(format!("snapnotable_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let arroyo = dir.join("arroyo.db");
        let c = Connection::open(&arroyo).unwrap();
        c.execute_batch("PRAGMA user_version = 102; CREATE TABLE conversation(id TEXT);")
            .unwrap();
        drop(c);
        let bytes = fs::read(&arroyo).unwrap();
        let _ = fs::remove_dir_all(&dir);

        let out = run_arroyo(bytes);
        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "{out:?}");
        assert_eq!(notes[0].metadata["status"], "SchemaTableAbsent");
        assert_eq!(notes[0].metadata["content_incomplete"], true);
        assert_eq!(
            notes[0].metadata["content_incomplete_reason"],
            "unvalidated"
        );
        assert_eq!(notes[0].metadata["table"], "conversation_message");
    }

    /// The friends list has its own validated point, 427, read from the one
    /// real `main.db` on file (Android, 2022-02-13) — one file, so one point.
    #[test]
    fn a_friend_table_past_the_validated_version_is_disclosed_and_still_parsed() {
        let dir = std::env::temp_dir().join(format!("snapfriendver_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("main.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch(
            "PRAGMA user_version = 999;
             CREATE TABLE Friend(username TEXT, userId TEXT, displayName TEXT, addedTimestamp INTEGER);
             INSERT INTO Friend VALUES ('thisisdfir','uid1','DFIR Guy',1721500000000);",
        )
        .unwrap();
        drop(c);
        let content = fs::read(&main).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let tmp = TempDb::write(&content, "snapchat").unwrap();
        let out = parse_main_friends(tmp.path(), Uuid::new_v4(), Uuid::new_v4(), "Android");

        let friends: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == "SnapchatContact")
            .collect();
        assert_eq!(friends.len(), 1);
        seance_core::test_support::assert_no_incompleteness_stamps(friends.iter().copied());
        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "{out:?}");
        assert_eq!(notes[0].metadata["type"], "SnapchatContactIncomplete");
        assert_eq!(notes[0].metadata["status"], "SchemaOutsideValidated");
        assert_eq!(notes[0].metadata["schema_version_seen"], 999);
        assert_eq!(notes[0].metadata["schema_version_supported"], "427..=427");
    }

    /// A `main.db` that is not Snapchat's gets no schema note: dozens of apps
    /// use that name, and a note would assert a Snapchat store on the strength
    /// of a generic filename.
    #[test]
    fn a_foreign_main_db_gets_no_schema_note() {
        let dir = std::env::temp_dir().join(format!("snapforeign_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let main = dir.join("main.db");
        let c = Connection::open(&main).unwrap();
        c.execute_batch("PRAGMA user_version = 5; CREATE TABLE Messages(body_xml TEXT);")
            .unwrap();
        drop(c);
        let content = fs::read(&main).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let tmp = TempDb::write(&content, "snapchat").unwrap();
        let out = parse_main_friends(tmp.path(), Uuid::new_v4(), Uuid::new_v4(), "Android");
        assert!(out.is_empty(), "{out:?}");
    }

    /// "Could not look" is not "in range". A locator that errors yields a
    /// note saying the store was compared against nothing — never silence,
    /// which is what an in-range store produces.
    #[test]
    fn a_version_the_store_would_not_answer_is_never_spent_as_in_range() {
        use schema::{assess, Observation, SchemaVersion};
        let fields = FieldMap::resolve(
            &["client_conversation_id", "sender_id", "creation_timestamp"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ARROYO_FIELDS,
        );
        let obs = Observation {
            version: SchemaVersion::Undetermined("PRAGMA user_version: disk I/O error".into()),
            fields: Some(&fields),
            required: ARROYO_REQUIRED,
            recovered: 4,
        };
        let out = assess(&ARROYO_SUPPORT, &obs, Uuid::new_v4(), Uuid::new_v4());
        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 2, "{out:?}");
        let version_note = notes
            .iter()
            .find(|a| a.metadata["status"] == "SchemaVersionUndetermined")
            .expect("the failed read is reported");
        assert!(version_note.metadata["schema_version_undetermined"]
            .as_str()
            .unwrap()
            .contains("disk I/O error"));
        assert!(version_note.metadata.get("schema_version_seen").is_none());
        assert!(version_note.metadata.get("content_incomplete").is_none());
        assert_eq!(version_note.metadata["records_recovered"], 4);
        // The four optional columns that were not in the (deliberately short)
        // column set are disclosed on their own note, without a stamp.
        let fields_note = notes
            .iter()
            .find(|a| a.metadata["status"] == "SchemaOptionalFieldsUnresolved")
            .expect("the absent optional columns are disclosed");
        assert!(fields_note.metadata.get("content_incomplete").is_none());
    }

    /// A version below the validated range is called below it, not above.
    #[test]
    fn a_version_below_the_validated_range_is_disclosed_as_older() {
        let out = run_arroyo(arroyo_bytes_with(50, "sender_id"));
        assert_eq!(messages(&out).len(), 1);
        let notes = schema_notes(&out);
        assert_eq!(notes.len(), 1, "{out:?}");
        assert_eq!(notes[0].metadata["status"], "SchemaOutsideValidated");
        assert_eq!(notes[0].metadata["schema_version_seen"], 50);
        assert!(notes[0].metadata["detail"]
            .as_str()
            .unwrap()
            .contains("OLDER"));
        assert!(notes[0].metadata.get("content_incomplete").is_none());
    }

    /// The corpus-diff anchor, gated on `SEANCE_SNAPCHAT_SAMPLES` (a directory
    /// holding `android/arroyo.db`, `android/main.db` (+ `-wal`) and
    /// `ios/arroyo.db`, extracted as VALIDATION.md records). Both real arroyo
    /// stores read 102 and every column the parser builds its query from
    /// resolves, so a genuine store carries no schema note; the measured row
    /// counts are exact, so a duplicated or dropped row fails here.
    #[test]
    fn the_real_snapchat_stores_read_the_validated_version_and_every_field_resolves() {
        use seance_core::data_source::FileDataSource;
        use seance_core::test_support::corpus;

        let Some(dir) = corpus::dir("SEANCE_SNAPCHAT_SAMPLES") else {
            return;
        };
        let run = |rel: &str, name: &str| {
            let path = dir.join(rel);
            assert!(
                path.is_file(),
                "{} is missing from the corpus",
                path.display()
            );
            let ds: std::sync::Arc<dyn DataSource> =
                std::sync::Arc::new(FileDataSource::new(path).unwrap());
            let art = Artifact::new(
                Uuid::new_v4(),
                ArtifactType::FileEntry,
                Some(ds),
                json!({ "name": name }),
            );
            SnapchatParser.process(&art).unwrap()
        };

        let android = run("android/arroyo.db", "arroyo.db");
        assert_eq!(messages(&android).len(), 7, "{android:?}");
        assert!(schema_notes(&android).is_empty(), "{android:?}");
        seance_core::test_support::assert_no_incompleteness_stamps(android.iter());

        let ios = run("ios/arroyo.db", "arroyo.db");
        assert_eq!(messages(&ios).len(), 2, "{ios:?}");
        assert!(schema_notes(&ios).is_empty(), "{ios:?}");
        seance_core::test_support::assert_no_incompleteness_stamps(ios.iter());

        let main = run("android/main.db", "main.db");
        let friends = main
            .iter()
            .filter(|a| a.metadata["type"] == "SnapchatContact")
            .count();
        assert_eq!(friends, 3, "{main:?}");
        assert!(schema_notes(&main).is_empty(), "{main:?}");
        seance_core::test_support::assert_no_incompleteness_stamps(main.iter());
    }

    /// B2-124: the database was read with `read_capped` and staged without ever
    /// comparing what came back against what the source declared. On Snapchat,
    /// where most message bodies are gone by design, an undersold message list
    /// is especially easy to mistake for the extraction ceiling.
    #[test]
    fn a_short_read_arroyo_marks_every_record_it_produced() {
        let ds: std::sync::Arc<dyn DataSource> = std::sync::Arc::new(truncated(arroyo_bytes()));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "arroyo.db" }),
        );
        let out = SnapchatParser.process(&art).unwrap();

        let msg = out
            .iter()
            .find(|a| a.metadata["subtype"] == "chat_message")
            .expect("the readable prefix still parses");
        assert_eq!(
            msg.metadata["content_incomplete"], true,
            "a message pulled out of a partial database must carry that fact"
        );
        assert_eq!(msg.metadata["content_incomplete_reason"], "short_read");
        assert!(
            out.iter()
                .any(|a| a.metadata["status"] == "DatabaseNotStagedInFull"),
            "a partial spill must be reported in its own right"
        );
    }

    /// The counterpart: a database read whole stays unmarked.
    #[test]
    fn a_complete_arroyo_carries_no_incompleteness_marks() {
        let ds: std::sync::Arc<dyn DataSource> = std::sync::Arc::new(
            seance_core::data_source::ByteSliceDataSource::new(arroyo_bytes()),
        );
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "arroyo.db" }),
        );
        let out = SnapchatParser.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].metadata.get("content_incomplete").is_none());
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
    /// that never had Snapchat produces, so a damaged database was reported as an
    /// app that was never installed — an exculpatory finding nobody established.
    ///
    /// Against the unfixed code this returns an empty vector.
    #[test]
    fn a_corrupt_store_is_not_reported_as_a_device_without_the_app() {
        let ds: std::sync::Arc<dyn DataSource> =
            std::sync::Arc::new(seance_core::data_source::ByteSliceDataSource::new(
                corrupt_the_catalogue(arroyo_bytes()),
            ));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "arroyo.db" }),
        );
        let out = SnapchatParser.process(&art).unwrap();

        assert!(
            !out.is_empty(),
            "an unreadable Snapchat store must not render as a device that never had Snapchat"
        );
        let marker = out
            .iter()
            .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
            .expect("the store was identified and not examined; that must be stated");
        assert_eq!(marker.metadata["type"], json!("SnapchatIncomplete"));
        assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    }
}
