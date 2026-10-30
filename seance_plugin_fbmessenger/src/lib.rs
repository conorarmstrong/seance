#![forbid(unsafe_code)]
//! Facebook Messenger message parser: the legacy Android `threads_db2` store
//! and the newer `msys` / lightspeed store.
//!
//! [`FbMessengerParser`] self-selects by basename and parses the `messages`
//! table into `chat_message`
//! [`ParsedRecord`](ArtifactType::ParsedRecord)s. Columns are resolved at
//! runtime through a field map, so a renamed column is reported by name on a
//! `ParserStaleWarning` record while the rows still walk without it — never a
//! silent empty result, and never a guessed value.
//!
//! Three shapes are recognised, as `StoreKind` names them:
//!
//! - **`threads_db2`** — the legacy Android store. `messages`: `text` (body),
//!   `sender` (a JSON object carrying the sender's `user_key` and `name`),
//!   `timestamp_ms` (Unix **milliseconds**), `thread_key` (conversation),
//!   `msg_type`.
//! - **`msys_database_*.db` / `lightspeed-*.db`** — the newer store, Android
//!   and iOS. Same parse path; the sender is an **id**, resolved through a
//!   contacts table when one is present so a message can name a person rather
//!   than a number, and left as the id when it is not.
//! - **`lightspeed-*.db.enc`** — the iOS store encrypted at rest. Unreadable
//!   without the device keychain key, so an identification record is emitted
//!   saying it exists and what would open it, rather than nothing.
//!
//! Direction is not a simple per-row flag in either schema, so the sender
//! identity is surfaced without asserting a direction.
//!
//! This doc previously said the `msys` store was "out of scope here" while
//! `StoreKind::Msys` took the real parse path twelve lines away, which is
//! `DOC-023`: it would have led the next person to write a second
//! implementation of a path that already existed.
//!
//! # Honesty & robustness
//!
//! A non-Messenger file, a missing `messages` table, or corrupt rows never panic
//! and never fail the pipeline.

use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::adopt::inline_marker::field_drift_marker;
use seance_sqlite_util::{
    artifact_name, is_directory_entry, open_readonly, probe_catalogue, probe_columns, probe_table,
    query_failed_marker, stage_sqlite_db, unreadable_store_marker, ChatMessage, FieldMap, Presence,
    RowDrops, SqliteEntry, MAX_DB_BYTES,
};
use serde_json::json;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

pub struct FbMessengerParser;

/// The parser identity a schema warning is filed under.
///
/// No schema-version window is declared for Messenger: no real `threads_db2`,
/// `msys_database_*.db` or `lightspeed-*.db` has been observed on any corpus
/// this parser was run against, and a window nobody observed would be a
/// fabrication. Until one is, drift is caught by the column maps alone, and a
/// store outside them is reported by field rather than by version.
const SCHEMA_APP: &str = "facebook-messenger";

/// The logical fields each table is read through, with the physical column
/// names that have carried them across the `threads_db2` and `msys` shapes.
/// Candidate order is preference order. A rename in a newer app build is then
/// one more candidate here, not a code path — and until it is added, the field
/// is reported as unresolved rather than read as empty.
const MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("text", &["text"]),
    ("timestamp", &["timestamp_ms", "timestamp"]),
    ("thread", &["thread_key", "thread_id"]),
    ("sender", &["sender", "sender_id"]),
];
const CONTACT_FIELDS: &[(&str, &[&str])] = &[
    ("id", &["id", "contact_id"]),
    (
        "name",
        &["name", "display_name", "normalized_name_for_search"],
    ),
];

/// One table's logical-to-physical column map, resolved against the store.
struct Fields {
    table: &'static str,
    map: FieldMap,
}

impl Fields {
    /// Resolve `specs` against the columns actually present. `Err` carries the
    /// reason the column list itself would not read: that is "could not
    /// look", and the caller must not spend it as "the columns are gone".
    fn resolve(
        conn: &Connection,
        table: &'static str,
        specs: &[(&str, &[&str])],
    ) -> Result<Self, String> {
        let present = probe_columns(conn, table)?;
        Ok(Self {
            table,
            map: FieldMap::resolve(&present, specs),
        })
    }

    /// The physical column for `logical`, or the SQL literal `NULL`: usable in
    /// an ORDER BY as well as a SELECT.
    fn col(&self, logical: &str) -> String {
        self.map
            .column(logical)
            .map(str::to_string)
            .unwrap_or_else(|| "NULL".to_string())
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

impl ForensicsModule for FbMessengerParser {
    fn id(&self) -> &str {
        "plugin.messaging.fb_messenger"
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
        let Some(kind) = messenger_db_kind(name) else {
            return Ok(Vec::new());
        };
        if is_directory_entry(artifact) {
            return Ok(Vec::new());
        }

        // The modern iOS store (`lightspeed-*.db.enc`) is encrypted at rest. We
        // cannot read messages without the keychain key, but we MUST document
        // that a Messenger message store exists — surface it rather than drop it.
        // Judged from the filename alone, so it is answered before any read.
        if kind == StoreKind::EncryptedLightspeed {
            debug!("FbMessengerParser flagging encrypted store {name}");
            return Ok(vec![encrypted_record(artifact.case_id, artifact.id, name)]);
        }

        debug!("FbMessengerParser inspecting {name} ({kind:?})");
        // The shared gate skips artifacts with no reachable content, probes the
        // SQLite magic with a LOOPING read (a windowed or container-backed
        // source may answer a 16-byte request with 4), then stages the database
        // with its `-wal` sibling — a seized msys/threads store usually still
        // holds its most recent messages uncheckpointed — and records whether
        // it was staged in full. SQLite opens a truncated file and answers from
        // the pages it can reach, so without that record the surviving rows
        // read as the whole message store (B2-124).
        let temp = match stage_sqlite_db(artifact, "fbm", MAX_DB_BYTES) {
            SqliteEntry::Staged(temp) => temp,
            // A msys store whose FULL header is not SQLite's is encrypted (or a
            // corrupt copy); record it so the store is still on the case file.
            //
            // The variant is load-bearing: a source that ran out before sixteen
            // bytes has shown us no header at all and lands in
            // `SqliteEntry::HeaderUnreadable`, which cannot reach this arm.
            // This branch once accepted a short read as proof of encryption,
            // and a four-byte file then produced an "EncryptedMessengerDatabase"
            // record asserting an encrypted Messenger store was present — a
            // claim the evidence does not support, and one an examiner has no
            // way to see through. It is now impossible to write that mistake
            // back in without deleting a match arm.
            SqliteEntry::NotSqlite { .. } if kind == StoreKind::Msys => {
                return Ok(vec![encrypted_record(artifact.case_id, artifact.id, name)])
            }
            // `threads_db2` / `msys*.db` / `lightspeed-*.db` name Messenger and
            // nothing else, and the header matched, so this is a Messenger
            // store this tool identified and did not examine. An empty list
            // here reads exactly like a phone that never had Messenger.
            SqliteEntry::StagingFailed(e) => {
                return Ok(vec![unreadable_store_marker(
                    artifact.case_id,
                    artifact.id,
                    "FacebookMessengerIncomplete",
                    format!("the Messenger database `{name}` carried the SQLite header and could not be staged for examination: {e}"),
                )])
            }
            _ => return Ok(Vec::new()),
        };
        let mut out = parse_messages(temp.path(), artifact.case_id, artifact.id, kind);
        temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        Ok(out)
    }
}

/// Which Messenger message store a filename denotes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoreKind {
    /// Legacy Android store (`threads_db2`): messages table with a JSON `sender`.
    ThreadsDb2,
    /// Newer `msys`/lightspeed store, decrypted — Android (`msys_database_*.db`)
    /// or iOS (`lightspeed-*.db`). Sender is an id resolved via a contacts table.
    Msys,
    /// iOS lightspeed store encrypted at rest (`lightspeed-*.db.enc`).
    EncryptedLightspeed,
}

/// Classify a filename as a Facebook Messenger store, or `None`. Matches on the
/// basename so a full backup path still resolves.
fn messenger_db_kind(name: &str) -> Option<StoreKind> {
    let lower = name.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or("");
    if base == "threads_db2" {
        return Some(StoreKind::ThreadsDb2);
    }
    if base.starts_with("lightspeed-") && base.ends_with(".db.enc") {
        return Some(StoreKind::EncryptedLightspeed);
    }
    if base.ends_with(".db") && (base.starts_with("lightspeed-") || base.starts_with("msys")) {
        return Some(StoreKind::Msys);
    }
    None
}

/// Identification record for an encrypted (unreadable) Messenger store, so the
/// examiner knows it exists and can pursue the iOS keychain key. Mirrors the
/// WeChat encrypted-database flag.
fn encrypted_record(case_id: Uuid, parent_id: Uuid, name: &str) -> Artifact {
    seance_sqlite_util::encrypted_store_record(
        case_id,
        parent_id,
        "Facebook Messenger",
        "iOS Data Protection (per-file key in the keychain)",
        "Encrypted lightspeed/msys store. Messages are unreadable without the device keychain \
         key; decrypt the file, then re-ingest to parse.",
        format!("Facebook Messenger store (encrypted): {name}"),
        &[("store", serde_json::json!("msys/lightspeed"))],
    )
}

/// From a Messenger `sender` JSON object, return `(name, user_key)`.
fn parse_sender(raw: &str) -> (Option<String>, Option<String>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return (None, None);
    };
    let name = v.get("name").and_then(|x| x.as_str()).map(String::from);
    let key = v.get("user_key").and_then(|x| x.as_str()).map(String::from);
    (name, key)
}

/// Read a column as an optional string, coercing integers/reals. `msys` stores
/// `thread_key`/`sender_id` as integers where `threads_db2` used text, so a
/// plain `get::<String>` would error on the newer store.
///
/// The shared readers, under this parser's names (ROADMAP §5.11: the one-line
/// wrappers that used to stand here are gone). `col_i64` tolerates a
/// text-encoded number.
use seance_sqlite_util::{row_i64_text_ok as col_i64, row_text as col_str};

/// The record type every finding about the `contacts` lookup is filed under,
/// never the walk's own `FacebookMessenger` (which would form a phantom thread).
const CONTACT_INCOMPLETE_TYPE: &str = "FacebookMessengerContactIncomplete";

/// `sender_id -> display name` from a `msys` contacts table, when present, so a
/// numeric sender can be named. Column names are detected at runtime.
///
/// Returns the map alongside the number of contact rows that would not decode.
/// A lost contact row is a lost identity: the messages that sender id sent are
/// then attributed to a bare numeric key, with nothing to say the name was on
/// the device but unreadable (B3-023).
///
/// The third element is the one record about the lookup itself — schema drift
/// in `contacts`, or a table, column list or query that would not read: the
/// messages are then attributed by numeric id, and the marker says why. Each
/// of those used to leave the name map empty with no record, so "the device
/// held no names" and "the names were not looked up" read alike (HUNT-225).
fn load_contacts(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
) -> (
    std::collections::HashMap<String, String>,
    RowDrops,
    Option<Artifact>,
) {
    let mut map = std::collections::HashMap::new();
    let mut drops = RowDrops::new();
    // An absent `contacts` table is a store shape, not drift: names are simply
    // not resolvable. A present one is held to the column map.
    let could_not_look = |detail: String| {
        Some(unreadable_store_marker(
            case_id,
            parent_id,
            CONTACT_INCOMPLETE_TYPE,
            detail,
        ))
    };
    match probe_table(conn, "contacts") {
        Presence::Present => {}
        Presence::Absent => return (map, drops, None),
        Presence::Undetermined(why) => {
            return (
                map,
                drops,
                could_not_look(format!(
                    "whether the Messenger store holds a `contacts` table could not be \
                     established, so senders are shown by numeric id: {why}"
                )),
            )
        }
    }
    let fields = match Fields::resolve(conn, "contacts", CONTACT_FIELDS) {
        Ok(fields) => fields,
        Err(why) => {
            return (
                map,
                drops,
                could_not_look(format!(
                    "the Messenger `contacts` table is present and its column list would not \
                     read, so senders are shown by numeric id and no name was looked up: {why}"
                )),
            )
        }
    };
    if !fields.map.all_resolved() {
        return (map, drops, fields.drift_marker(case_id, parent_id, 0));
    }
    let id_col = fields.col("id");
    let name_col = fields.col("name");
    let query_failed = |e: rusqlite::Error| {
        Some(query_failed_marker(
            case_id,
            parent_id,
            CONTACT_INCOMPLETE_TYPE,
            "contacts",
            &e.to_string(),
        ))
    };
    let mut stmt = match conn.prepare(&format!("SELECT {id_col}, {name_col} FROM contacts")) {
        Ok(stmt) => stmt,
        Err(e) => return (map, drops, query_failed(e)),
    };
    let rows = match stmt.query_map([], |r| Ok((col_str(r, 0), col_str(r, 1)))) {
        Ok(rows) => rows,
        Err(e) => return (map, drops, query_failed(e)),
    };
    for row in rows {
        let (k, v) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Messenger: skipping undecodable contacts row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        if let (Some(k), Some(v)) = (k, v) {
            if !v.is_empty() {
                map.insert(k, v);
            }
        }
    }
    (map, drops, None)
}

/// The record that says a Messenger store was identified and could not be read.
/// Zero artifacts would render identically to a device that never had Messenger.
fn unreadable(case_id: Uuid, parent_id: Uuid, detail: String) -> Vec<Artifact> {
    vec![unreadable_store_marker(
        case_id,
        parent_id,
        "FacebookMessengerIncomplete",
        detail,
    )]
}

/// Parse the `messages` table of a decrypted Messenger store. Handles both the
/// legacy `threads_db2` schema (JSON `sender`) and the newer `msys`/lightspeed
/// schema (numeric `sender_id` resolved via `contacts`). Columns are resolved
/// through the field map, so a renamed one is reported by name and the rows
/// still walk without it — never a guessed value, never a silent empty list.
fn parse_messages(path: &Path, case_id: Uuid, parent_id: Uuid, kind: StoreKind) -> Vec<Artifact> {
    // Named as Messenger evidence, so a store that will not open or will not
    // answer is unreadable, not an account with no messages. `table_columns`
    // returned {} on a PRAGMA failure, which failed the column check below and
    // produced the same silence a clean absence would (B8-039).
    let conn = match open_readonly(path) {
        Ok(conn) => conn,
        Err(e) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the Messenger database is named as evidence and would not open: {e}"),
            )
        }
    };
    if let Err(why) = probe_catalogue(&conn) {
        return unreadable(case_id, parent_id, format!("the Messenger database opened and its schema catalogue would not read, so whether it holds messages is undetermined rather than answered: {why}"));
    }
    match probe_table(&conn, "messages") {
        Presence::Absent => return Vec::new(),
        Presence::Undetermined(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the `messages` table could not be looked for: {why}"),
            )
        }
        Presence::Present => {}
    }
    // Schema-drift defence: every column the walk reads comes through the
    // field map, so a renamed one becomes `NULL` in the SELECT and a named
    // entry on the marker below. A missing `text` or timestamp used to end the
    // walk with an empty list — silence indistinguishable from an account with
    // no messages.
    let fields = match Fields::resolve(&conn, "messages", MESSAGE_FIELDS) {
        Ok(fields) => fields,
        Err(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("`messages` is present and its column list would not read: {why}"),
            )
        }
    };
    let text_col = fields.col("text");
    let ts_col = fields.col("timestamp");
    let thread_col = fields.col("thread");
    let sender_col = fields.col("sender");
    // Which sender shape the store has: a JSON object (`sender`) or a numeric
    // id resolved through `contacts` (`sender_id`).
    let msys_sender = fields.map.column("sender") == Some("sender_id");
    let (contacts, contact_drops, contact_drift) = if msys_sender {
        load_contacts(&conn, case_id, parent_id)
    } else {
        (std::collections::HashMap::new(), RowDrops::new(), None)
    };

    let select = format!(
        "SELECT rowid, {thread_col}, {sender_col}, {text_col}, {ts_col} FROM messages \
         ORDER BY {ts_col}"
    );
    // The table and its columns are established, so a statement that will not
    // prepare or run is a store this tool could not read — never an empty one
    // (HUNT-189). The contact lookup's own findings travel with it.
    let query_failed = |e: rusqlite::Error| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            "FacebookMessengerIncomplete",
            "messages",
            &e.to_string(),
        )];
        out.extend(fields.drift_marker(case_id, parent_id, 0));
        out
    };
    let mut stmt = match conn.prepare(&select) {
        Ok(stmt) => stmt,
        Err(e) => return query_failed(e),
    };
    let rows = match stmt.query_map([], |r| {
        Ok((
            col_i64(r, 0).unwrap_or_default(),
            col_str(r, 1),
            col_str(r, 2),
            col_str(r, 3),
            col_i64(r, 4),
        ))
    }) {
        Ok(rows) => rows,
        Err(e) => return query_failed(e),
    };

    let mut out = Vec::new();
    // Rows the query returned that could not be decoded. `flatten()` used to
    // swallow these, so the message count read as exact (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (id, thread, sender_raw, text, ts_ms) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Messenger: skipping undecodable messages row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        let (sender_name, sender_key) = match (msys_sender, sender_raw) {
            (false, Some(js)) => parse_sender(&js),
            (true, Some(sid)) => (contacts.get(&sid).cloned(), Some(sid)),
            _ => (None, None),
        };
        out.push(build_record(
            case_id,
            parent_id,
            id,
            thread,
            sender_name,
            sender_key,
            text,
            ts_ms,
            kind,
        ));
    }
    // Counted before either marker joins the list, so a marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        "FacebookMessengerIncomplete",
        "messages",
        recovered,
    ));
    out.extend(contact_drops.marker(
        case_id,
        parent_id,
        CONTACT_INCOMPLETE_TYPE,
        "contacts",
        contacts.len(),
    ));
    out.extend(fields.drift_marker(case_id, parent_id, recovered));
    out.extend(contact_drift);
    out
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    id: i64,
    thread: Option<String>,
    sender_name: Option<String>,
    sender_key: Option<String>,
    text: Option<String>,
    ts_ms: Option<i64>,
    kind: StoreKind,
) -> Artifact {
    let date_s = ts_ms.filter(|&d| d > 0).map(|d| d.div_euclid(1000));
    let contact = sender_name.clone().or_else(|| sender_key.clone());
    let platform = match kind {
        StoreKind::ThreadsDb2 => "Android",
        StoreKind::Msys => "msys/lightspeed",
        StoreKind::EncryptedLightspeed => "iOS",
    };

    // No `from_me`: neither `threads_db2` nor the msys tables carry a per-row
    // direction flag this parser can read, and the owning account is not
    // established here — so `is_from_me`/`direction` are omitted rather than
    // inferred from the sender key.
    ChatMessage::new("FacebookMessenger", "Facebook Messenger", platform)
        .text(text)
        .date_secs(date_s)
        .contact(contact)
        .chat_identifier(thread)
        .extra("rowid", json!(id))
        .extra("sender_key", json!(sender_key))
        .into_artifact(case_id, parent_id)
}

#[cfg(test)]
mod tests;
