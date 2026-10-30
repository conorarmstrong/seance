//! Signal for iOS: the SQLCipher 4 store `grdb/signal.sqlite`, opened with the
//! raw key spec an examiner supplies for that one file (`HUNT-227`), and its
//! GRDB schema read.
//!
//! # What is graded, and on what
//!
//! Decryption is graded on a real store (`VALIDATION.md` `SIGNAL-IOS-1`): the
//! Magnet 2022 iPhone 8's 305 pages and 38 committed WAL frames all
//! authenticate. The **schema** is graded structurally only: that store's
//! `model_TSInteraction` holds no rows, so the tables and every column this
//! reader resolves were found on a real Signal-iOS database, and no message
//! row written by the app has been read by it. The schema record says so
//! (`IOS_SCHEMA_SUPPORT` is `Unranged`), and the reader claims no direction for
//! a message: Signal-iOS keeps it in the row's class code (`recordType`),
//! whose values no real row here has confirmed.
//!
//! # What is read
//!
//! `model_TSInteraction` (messages: body, timestamps, thread, author),
//! `model_TSThread` (conversations), `model_SignalRecipient` joined to
//! `model_OWSUserProfile` (contacts and profile names), and `grdb_migrations`
//! (the schema's migration history, which is where GRDB keeps its version —
//! `PRAGMA user_version` is 0). The profile key and avatar columns are key
//! material and pointers, and are not read.

use crate::schema_support::{SchemaBound, SchemaCheck, SchemaSupport, SchemaVersion};
use rusqlite::Connection;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_sqlite_util::{probe_columns, unix_seconds_from_magnitude, FieldMap};
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// What this parser may say about a Signal-iOS schema version: nothing ranged.
pub(crate) const IOS_SCHEMA_SUPPORT: SchemaSupport = SchemaSupport {
    app: "signal-ios",
    bound: SchemaBound::Unranged {
        why: "the one Signal for iOS store this project has decrypted (the Magnet 2022 \
              iPhone 8, VALIDATION.md SIGNAL-IOS-1) holds no messages, so its GRDB tables \
              and columns were read and no message row written by the app has been; the \
              schema is graded structurally",
    },
};

/// Logical message fields and the `model_TSInteraction` columns that carry
/// them on the real store.
const INTERACTION_FIELDS: &[(&str, &[&str])] = &[
    ("unique_id", &["uniqueId"]),
    ("record_type", &["recordType"]),
    ("text", &["body"]),
    ("date", &["timestamp"]),
    ("received_at", &["receivedAtTimestamp"]),
    ("thread", &["uniqueThreadId"]),
    ("author_phone", &["authorPhoneNumber"]),
    ("author_uuid", &["authorUUID"]),
    ("read", &["read"]),
];

/// Without these a row is not an evidentiary message.
const REQUIRED_FIELDS: &[&str] = &["text", "date", "thread"];

/// Row budget per table.
const MAX_ROWS: usize = 500_000;

/// Whether an open store carries Signal-iOS's GRDB schema.
pub(crate) fn is_grdb_signal_schema(conn: &Connection) -> bool {
    ["model_TSInteraction", "model_TSThread"].iter().all(|t| {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [t],
            |_| Ok(()),
        )
        .is_ok()
    })
}

/// Facts about the decryption that the summary carries.
pub(crate) struct DecryptionFacts {
    pub pages: usize,
    pub integrity_verified: bool,
    pub integrity_statement: String,
    /// `None` when the store had no reachable `-wal`.
    pub wal: Option<WalFacts>,
}

pub(crate) struct WalFacts {
    pub frames_committed: usize,
    pub frames_not_committed: usize,
    pub integrity_verified: bool,
    pub integrity_statement: String,
}

fn opt_text(row: &rusqlite::Row, col: Option<&str>) -> Option<String> {
    col.and_then(|c| row.get::<_, Option<String>>(c).ok().flatten())
        .filter(|s| !s.is_empty())
}

fn opt_i64(row: &rusqlite::Row, col: Option<&str>) -> Option<i64> {
    col.and_then(|c| row.get::<_, Option<i64>>(c).ok().flatten())
}

fn record(case_id: Uuid, parent_id: Uuid, subtype: &str, meta: Map<String, Value>) -> Artifact {
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype(subtype)
}

fn count(conn: &Connection, table: &str) -> Option<i64> {
    conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| {
        r.get(0)
    })
    .ok()
}

/// Read a decrypted Signal-iOS store into records.
pub(crate) fn parse_ios_store(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    facts: &DecryptionFacts,
) -> Vec<Artifact> {
    let mut out = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // ── messages ─────────────────────────────────────────────────────────
    let cols = probe_columns(conn, "model_TSInteraction").unwrap_or_else(|e| {
        notes.push(e);
        Default::default()
    });
    let fields = FieldMap::resolve(&cols, INTERACTION_FIELDS);
    let mut message_count = 0usize;
    let mut messages_truncated = false;
    if fields.column("text").is_some() && fields.column("thread").is_some() {
        let sql = format!(
            "SELECT * FROM model_TSInteraction ORDER BY id LIMIT {}",
            MAX_ROWS + 1
        );
        match conn.prepare(&sql) {
            Ok(mut stmt) => {
                let rows = stmt.query_map([], |row| {
                    let mut meta = Map::new();
                    meta.insert("type".into(), json!("Signal"));
                    meta.insert("service".into(), json!("Signal"));
                    meta.insert("platform".into(), json!("ios"));
                    meta.insert("store".into(), json!("model_TSInteraction"));
                    meta.insert("rowid".into(), json!(row.get::<_, Option<i64>>("id")?));
                    if let Some(v) = opt_text(row, fields.column("unique_id")) {
                        meta.insert("unique_id".into(), json!(v));
                    }
                    if let Some(v) = opt_i64(row, fields.column("record_type")) {
                        meta.insert("record_type_code".into(), json!(v));
                    }
                    let text = opt_text(row, fields.column("text"));
                    if let Some(t) = &text {
                        meta.insert("text".into(), json!(t));
                    }
                    let thread = opt_text(row, fields.column("thread"));
                    if let Some(t) = &thread {
                        meta.insert("thread_unique_id".into(), json!(t));
                        meta.insert("chat_identifier".into(), json!(t));
                    }
                    let author = opt_text(row, fields.column("author_phone"))
                        .or_else(|| opt_text(row, fields.column("author_uuid")));
                    if let Some(a) = &author {
                        meta.insert("author".into(), json!(a));
                        meta.insert("sender".into(), json!(a));
                    }
                    if let Some(v) = opt_text(row, fields.column("author_uuid")) {
                        meta.insert("author_uuid".into(), json!(v));
                    }
                    if let Some(secs) =
                        opt_i64(row, fields.column("date")).and_then(unix_seconds_from_magnitude)
                    {
                        meta.insert("date".into(), json!(secs));
                        if let Some(dt) = chrono::DateTime::from_timestamp(secs, 0) {
                            meta.insert("date_rfc3339".into(), json!(dt.to_rfc3339()));
                        }
                    }
                    if let Some(secs) = opt_i64(row, fields.column("received_at"))
                        .and_then(unix_seconds_from_magnitude)
                    {
                        meta.insert("received_at".into(), json!(secs));
                    }
                    if let Some(r) = opt_i64(row, fields.column("read")) {
                        meta.insert("read".into(), json!(r != 0));
                    }
                    meta.insert(
                        "direction_basis".into(),
                        json!(
                            "not stated: Signal for iOS records a message's direction in its \
                             class code (recordType), which no real row has confirmed for this \
                             parser; the author column is present on received messages"
                        ),
                    );
                    let label = text.clone().unwrap_or_else(|| "(no body)".to_string());
                    meta.insert(
                        "name".into(),
                        json!(format!(
                            "Signal (iOS) message: {}",
                            label.chars().take(80).collect::<String>()
                        )),
                    );
                    Ok(meta)
                });
                match rows {
                    Ok(rows) => {
                        for row in rows {
                            match row {
                                Ok(meta) => {
                                    if message_count == MAX_ROWS {
                                        messages_truncated = true;
                                        break;
                                    }
                                    message_count += 1;
                                    out.push(record(case_id, parent_id, "message", meta));
                                }
                                Err(e) => notes.push(format!("a message row would not read: {e}")),
                            }
                        }
                    }
                    Err(e) => notes.push(format!("model_TSInteraction would not query: {e}")),
                }
            }
            Err(e) => notes.push(format!("model_TSInteraction would not prepare: {e}")),
        }
    }

    // ── threads ──────────────────────────────────────────────────────────
    let mut thread_count = 0usize;
    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT * FROM model_TSThread ORDER BY id LIMIT {MAX_ROWS}"
    )) {
        let tcols = probe_columns(conn, "model_TSThread").unwrap_or_default();
        let has = |c: &str| tcols.contains(&c.to_ascii_lowercase());
        let rows = stmt.query_map([], |row| {
            let mut meta = Map::new();
            meta.insert("type".into(), json!("SignalThread"));
            meta.insert("service".into(), json!("Signal"));
            meta.insert("platform".into(), json!("ios"));
            meta.insert("store".into(), json!("model_TSThread"));
            let get = |c: &str| {
                if has(c) {
                    row.get::<_, Option<String>>(c).ok().flatten()
                } else {
                    None
                }
            };
            if let Some(v) = get("uniqueId") {
                meta.insert("thread_unique_id".into(), json!(v));
            }
            let phone = get("contactPhoneNumber");
            let uuid = get("contactUUID");
            if let Some(v) = &phone {
                meta.insert("contact_phone_number".into(), json!(v));
            }
            if let Some(v) = &uuid {
                meta.insert("contact_uuid".into(), json!(v));
            }
            if has("groupModel") {
                let is_group = row
                    .get::<_, Option<Vec<u8>>>("groupModel")
                    .ok()
                    .flatten()
                    .is_some();
                meta.insert("is_group".into(), json!(is_group));
            }
            if has("isArchived") {
                if let Ok(Some(a)) = row.get::<_, Option<i64>>("isArchived") {
                    meta.insert("is_archived".into(), json!(a != 0));
                }
            }
            let who = phone
                .or(uuid)
                .unwrap_or_else(|| "(group or unnamed)".into());
            meta.insert(
                "name".into(),
                json!(format!("Signal (iOS) conversation: {who}")),
            );
            Ok(meta)
        });
        if let Ok(rows) = rows {
            for meta in rows.flatten() {
                thread_count += 1;
                out.push(record(case_id, parent_id, "thread", meta));
            }
        }
    }

    // ── contacts, with profile names ─────────────────────────────────────
    let mut contact_count = 0usize;
    let profile_sql = "SELECT r.recipientPhoneNumber AS phone, r.recipientUUID AS uuid, \
                       p.profileName AS given, p.familyName AS family, p.username AS username \
                       FROM model_SignalRecipient r LEFT JOIN model_OWSUserProfile p \
                       ON (p.recipientUUID IS NOT NULL AND p.recipientUUID = r.recipientUUID) \
                       OR (p.recipientPhoneNumber IS NOT NULL \
                           AND p.recipientPhoneNumber = r.recipientPhoneNumber) \
                       ORDER BY r.id";
    let plain_sql = "SELECT recipientPhoneNumber AS phone, recipientUUID AS uuid, \
                     NULL AS given, NULL AS family, NULL AS username \
                     FROM model_SignalRecipient ORDER BY id";
    let stmt = conn
        .prepare(profile_sql)
        .or_else(|_| conn.prepare(plain_sql));
    if let Ok(mut stmt) = stmt {
        let rows = stmt.query_map([], |row| {
            let phone: Option<String> = row.get("phone").ok().flatten();
            let uuid: Option<String> = row.get("uuid").ok().flatten();
            let given: Option<String> = row.get("given").ok().flatten();
            let family: Option<String> = row.get("family").ok().flatten();
            let username: Option<String> = row.get("username").ok().flatten();
            let mut meta = Map::new();
            meta.insert("type".into(), json!("SignalContact"));
            meta.insert("service".into(), json!("Signal"));
            meta.insert("platform".into(), json!("ios"));
            let identifier = phone.clone().or(uuid.clone()).unwrap_or_default();
            meta.insert("identifier".into(), json!(identifier));
            if let Some(v) = &phone {
                meta.insert("phone_number".into(), json!(v));
            }
            if let Some(v) = &uuid {
                meta.insert("uuid".into(), json!(v));
            }
            let profile = match (
                given.filter(|s| !s.is_empty()),
                family.filter(|s| !s.is_empty()),
            ) {
                (Some(g), Some(f)) => Some(format!("{g} {f}")),
                (Some(g), None) => Some(g),
                (None, Some(f)) => Some(f),
                (None, None) => None,
            };
            if let Some(p) = &profile {
                meta.insert("profile_name".into(), json!(p));
            }
            if let Some(u) = username {
                meta.insert("username".into(), json!(u));
            }
            let display = profile.clone().unwrap_or_else(|| identifier.clone());
            meta.insert("contact".into(), json!(display));
            meta.insert(
                "name".into(),
                json!(format!("Signal (iOS) contact: {display}")),
            );
            Ok(meta)
        });
        if let Ok(rows) = rows {
            for meta in rows.flatten().take(MAX_ROWS) {
                contact_count += 1;
                out.push(record(case_id, parent_id, "contact", meta));
            }
        }
    }

    // ── the schema statement ─────────────────────────────────────────────
    let migrations = count(conn, "grdb_migrations");
    let schema = SchemaCheck {
        support: &IOS_SCHEMA_SUPPORT,
        version: SchemaVersion::NotRead {
            locator: "grdb_migrations",
            why: "Signal for iOS records its schema as the list of GRDB migrations applied \
                  (grdb_migrations), not as a PRAGMA user_version number",
        },
        fields: &fields,
        required: REQUIRED_FIELDS,
        record_type: "SignalIncomplete",
        store: "model_TSInteraction",
    }
    .marker(case_id, parent_id, message_count);

    // ── the summary ──────────────────────────────────────────────────────
    let mut s = Map::new();
    s.insert("type".into(), json!("SignalSummary"));
    s.insert("service".into(), json!("Signal"));
    s.insert("platform".into(), json!("ios"));
    s.insert("file_name".into(), json!(file_name));
    s.insert("status".into(), json!("Decrypted"));
    s.insert("message_count".into(), json!(message_count));
    s.insert("thread_count".into(), json!(thread_count));
    s.insert("contact_count".into(), json!(contact_count));
    s.insert("schema_grading".into(), json!("structural"));
    if let Some(m) = migrations {
        s.insert("grdb_migrations".into(), json!(m));
    }
    if let Ok(last) = conn.query_row(
        "SELECT identifier FROM grdb_migrations ORDER BY rowid DESC LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    ) {
        s.insert("grdb_last_migration".into(), json!(last));
    }
    s.insert("pages".into(), json!(facts.pages));
    s.insert("integrity_verified".into(), json!(facts.integrity_verified));
    s.insert(
        "integrity_statement".into(),
        json!(facts.integrity_statement),
    );
    match &facts.wal {
        Some(w) => {
            s.insert("wal_frames_committed".into(), json!(w.frames_committed));
            s.insert(
                "wal_frames_not_committed".into(),
                json!(w.frames_not_committed),
            );
            s.insert("wal_integrity_verified".into(), json!(w.integrity_verified));
            s.insert(
                "wal_integrity_statement".into(),
                json!(w.integrity_statement),
            );
        }
        None => {
            s.insert("wal_frames_committed".into(), json!(0));
        }
    }
    s.insert(
        "credential_kind".into(),
        json!(seance_core::credential::CredentialKind::SignalIosKeySpec.as_str()),
    );
    s.insert("credential_source".into(), json!("supplied_for_this_run"));
    if messages_truncated {
        s.insert("truncated".into(), json!(true));
        s.insert("content_incomplete".into(), json!(true));
        s.insert(
            "content_incomplete_reason".into(),
            json!(seance_core::io::IncompleteReason::CapReached.as_str()),
        );
    }
    if !notes.is_empty() {
        s.insert("read_errors".into(), json!(notes));
        s.insert("counts_are_floor".into(), json!(true));
    }
    s.insert(
        "detail".into(),
        json!(format!(
            "The Signal for iOS store {file_name} was decrypted with a key spec supplied by an \
             examiner for this file; the key spec itself is not recorded. {message_count} \
             message(s), {thread_count} conversation(s) and {contact_count} contact(s) were \
             read from its GRDB schema. The schema is graded structurally: the tables and \
             columns read were found on a real Signal for iOS store, which held no messages, \
             so no message row written by the app has yet been compared against this reading."
        )),
    );
    s.insert(
        "name".into(),
        json!(format!("Signal (iOS) store decrypted: {file_name}")),
    );
    out.push(record(case_id, parent_id, "summary", s));
    out.extend(schema);
    out
}
