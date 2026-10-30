#![forbid(unsafe_code)]
//! LINE (Android `naver_line`) message parser.
//!
//! [`LineParser`] self-selects LINE's `naver_line` SQLite database and, when it
//! is a plain database, parses the `chat_history` table into `chat_message`
//! [`ParsedRecord`](ArtifactType::ParsedRecord)s. Columns are resolved at
//! runtime through a field map, so a column the schema lacks is **named** on a
//! schema note rather than silently read as empty — a wrong schema never yields
//! wrong records, and never yields a silent nothing either. An app-encrypted
//! (non-SQLite) database is flagged for triage.
//!
//! # Schema version
//!
//! No real LINE database is held by this project, so this parser declares **no
//! validated schema range**: a range endpoint not read out of a real file would
//! be a number copied from somewhere. It records the `PRAGMA user_version` it
//! sees on a `schema_support` note and states that it was compared against
//! nothing. The declaration gains a range when a device sample arrives.
//!
//! # Schema
//!
//! `chat_history`: `id`, `chat_id` (conversation), `from_mid` (sender's LINE
//! id), `content` (text), `created_time` (Unix **milliseconds**), `type`.
//! Direction is not stored per row (there is no is-from-me flag), so the sender
//! id is surfaced without asserting a direction.
//!
//! # Honesty & robustness
//!
//! A non-LINE file, a missing `chat_history` table, or corrupt rows never panic
//! and never fail the pipeline.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    artifact_name, open_readonly, probe_catalogue, probe_columns, probe_table, query_failed_marker,
    stage_sqlite_db, unreadable_store_marker, ChatMessage, FieldMap, Presence, RowDrops,
    SqliteEntry, MAX_DB_BYTES,
};
use serde_json::json;
use std::path::Path;
use tracing::debug;
use uuid::Uuid;

pub mod schema;
use schema::{
    assess, read_user_version, Observation, SchemaSupport, SupportBound, USER_VERSION_LOCATOR,
};

pub struct LineParser;

/// The record type every LINE incompleteness marker and schema note is filed
/// under — never `"LINE"`, which `seance_db` groups conversations on.
const INCOMPLETE_TYPE: &str = "LineIncomplete";

/// Every logical field read from `chat_history`, with the physical column(s)
/// that have carried it. Written from the schema description this parser was
/// built to; no real store has confirmed it (see `CHAT_HISTORY_SUPPORT`).
const CHAT_HISTORY_FIELDS: &[(&str, &[&str])] = &[
    ("conversation", &["chat_id"]),
    ("sender", &["from_mid"]),
    ("text", &["content"]),
    ("sent_at", &["created_time"]),
];

/// Without a body and a time a `chat_history` row is not a message record.
const CHAT_HISTORY_REQUIRED: &[&str] = &["text", "sent_at"];

const CHAT_HISTORY_SUPPORT: SchemaSupport = SchemaSupport {
    app: "line-android",
    store: "naver_line",
    table: "chat_history",
    record_type: INCOMPLETE_TYPE,
    locator: USER_VERSION_LOCATOR,
    bound: SupportBound::Unranged {
        why: "no real LINE database is held by this project, so no schema version has been \
              read out of one; the version seen is recorded, not ranged",
    },
};

impl ForensicsModule for LineParser {
    fn id(&self) -> &str {
        "plugin.messaging.line"
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
        if !is_line_db(name) {
            return Ok(Vec::new());
        }

        debug!("LineParser inspecting {name}");
        // The shared gate skips directories and artifacts with no reachable
        // content, probes the SQLite magic with a LOOPING read, then stages the
        // database with its `-wal` sibling and records whether it was staged in
        // full. SQLite opens a truncated file and answers from the pages it can
        // reach, so without that record the surviving rows read as the whole
        // chat history (B2-124).
        let temp = match stage_sqlite_db(artifact, "line", MAX_DB_BYTES) {
            SqliteEntry::Staged(temp) => temp,
            // A `naver_line` that carries a FULL header which is not SQLite's is
            // LINE's encrypted store — record that it was here rather than
            // saying nothing, which reads as a device with no LINE messages.
            // Matching this variant is what makes that judgement safe: a source
            // that ran out before sixteen bytes lands in
            // `SqliteEntry::HeaderUnreadable` instead, so a short read cannot
            // put a false encryption claim in the case file.
            SqliteEntry::NotSqlite { .. } => {
                return Ok(vec![encrypted_record(artifact.case_id, artifact.id)])
            }
            // `naver_line` names LINE and nothing else, and the header matched,
            // so this is a LINE store this tool identified and did not examine.
            // Saying nothing would read as a device with no LINE messages —
            // the same silence this parser already refuses for the encrypted
            // case one arm above.
            SqliteEntry::StagingFailed(e) => {
                return Ok(vec![unreadable_store_marker(
                    artifact.case_id,
                    artifact.id,
                    INCOMPLETE_TYPE,
                    format!("the LINE database `{name}` carried the SQLite header and could not be staged for examination: {e}"),
                )])
            }
            _ => return Ok(Vec::new()),
        };
        let mut out = parse_chat_history(temp.path(), artifact.case_id, artifact.id);
        temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        Ok(out)
    }
}

fn is_line_db(name: &str) -> bool {
    name.to_ascii_lowercase().rsplit('/').next().unwrap_or("") == "naver_line"
}

fn encrypted_record(case_id: Uuid, parent_id: Uuid) -> Artifact {
    seance_sqlite_util::encrypted_store_record(
        case_id,
        parent_id,
        "LINE",
        // All that was established is that a file named `naver_line` presented
        // a full 16-byte header which is not SQLite's. That is evidence the
        // store is encrypted and no evidence at all of the scheme, so the
        // record says exactly that. The copy this replaces omitted the field,
        // which beside WeChat's "SQLCipher" read as "not applicable".
        "not identified (a full non-SQLite header; the scheme was not established)",
        "Not a plain SQLite database; app-level decryption required to parse messages.",
        "LINE database (encrypted)".to_string(),
        &[],
    )
}

/// Read a column as an optional string, coercing integers/reals.
///
/// `chat_id` is an integer conversation id on several LINE generations and a
/// string on others; `from_mid` can be stored either way too. A plain
/// `get::<String>` errors on the integer form, which drops **every** row and
/// emits an empty parse with no marker.
///
/// The shared readers, under this parser's names (ROADMAP §5.11: the one-line
/// wrappers that used to stand here are gone). `col_i64` tolerates a
/// text-encoded number.
use seance_sqlite_util::{row_i64_text_ok as col_i64, row_text as col_str};

/// The record that says a LINE store was identified and could not be read.
/// Zero artifacts would render identically to a device that never had LINE.
fn unreadable(case_id: Uuid, parent_id: Uuid, detail: String) -> Vec<Artifact> {
    vec![unreadable_store_marker(
        case_id,
        parent_id,
        INCOMPLETE_TYPE,
        detail,
    )]
}

fn parse_chat_history(path: &Path, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    // Named as LINE evidence, so a store that will not open or will not answer
    // is unreadable, not a phone without LINE. `table_columns` returned {} on a
    // PRAGMA failure, so a damaged store produced the same silence as a clean
    // absence (B8-039).
    let conn = match open_readonly(path) {
        Ok(conn) => conn,
        Err(e) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the LINE database is named as evidence and would not open: {e}"),
            )
        }
    };
    if let Err(why) = probe_catalogue(&conn) {
        return unreadable(case_id, parent_id, format!("the LINE database opened and its schema catalogue would not read, so whether it holds messages is undetermined rather than answered: {why}"));
    }
    // The catalogue read, so an absent table is a finding — but `naver_line`
    // names LINE and nothing else, and silence here renders exactly like a
    // device with no LINE messages. Said, with the version seen.
    match probe_table(&conn, "chat_history") {
        Presence::Absent => {
            let obs = Observation {
                version: read_user_version(&conn),
                fields: None,
                required: CHAT_HISTORY_REQUIRED,
                recovered: 0,
            };
            return assess(&CHAT_HISTORY_SUPPORT, &obs, case_id, parent_id);
        }
        Presence::Undetermined(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("the `chat_history` table could not be looked for: {why}"),
            )
        }
        Presence::Present => {}
    }
    let cols = match probe_columns(&conn, "chat_history") {
        Ok(cols) => cols,
        Err(why) => {
            return unreadable(
                case_id,
                parent_id,
                format!("`chat_history` is present and its column list would not read: {why}"),
            )
        }
    };
    let fields = FieldMap::resolve(&cols, CHAT_HISTORY_FIELDS);
    let version = read_user_version(&conn);
    let assessment = |recovered: usize| {
        let obs = Observation {
            version: version.clone(),
            fields: Some(&fields),
            required: CHAT_HISTORY_REQUIRED,
            recovered,
        };
        assess(&CHAT_HISTORY_SUPPORT, &obs, case_id, parent_id)
    };
    // A table with neither a body nor a time is not the one this parser
    // knows; say so rather than manufacture rows from it.
    if CHAT_HISTORY_REQUIRED
        .iter()
        .all(|f| fields.column(f).is_none())
    {
        return assessment(0);
    }
    let id_col = if cols.contains("id") { "id" } else { "rowid" };
    // Every `NULL` below stands for a logical field the map recorded as
    // unresolved and the assessment names; naming a column the schema lacks
    // would fail prepare() and drop the whole conversation instead.
    let col = |logical: &str| fields.column(logical).unwrap_or("NULL");
    let chat_col = col("conversation");
    let from_col = col("sender");
    let text_col = col("text");
    let time_col = col("sent_at");
    let sql = format!(
        "SELECT {id_col}, {chat_col}, {from_col}, {text_col}, {time_col} FROM chat_history ORDER BY {time_col}"
    );
    // The table and its columns are established, so a statement that will not
    // prepare or run is a store this tool could not read — never an empty one
    // (HUNT-189).
    let query_failed = |e: rusqlite::Error| -> Vec<Artifact> {
        let mut out = vec![query_failed_marker(
            case_id,
            parent_id,
            INCOMPLETE_TYPE,
            "chat_history",
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
            col_i64(r, 0),
            col_str(r, 1),
            col_str(r, 2),
            col_str(r, 3),
            col_i64(r, 4),
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
        let (id, chat_id, from_mid, content, created_ms) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("LINE: skipping undecodable chat_history row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        out.push(build_record(
            case_id, parent_id, id, chat_id, from_mid, content, created_ms,
        ));
    }
    // Counted before the marker joins the list, so the marker never counts
    // itself as a recovered record.
    let recovered = out.len();
    out.extend(drops.marker(
        case_id,
        parent_id,
        INCOMPLETE_TYPE,
        "chat_history",
        recovered,
    ));
    out.extend(assessment(recovered));
    out
}

fn build_record(
    case_id: Uuid,
    parent_id: Uuid,
    id: Option<i64>,
    chat_id: Option<String>,
    from_mid: Option<String>,
    content: Option<String>,
    created_ms: Option<i64>,
) -> Artifact {
    let date_s = created_ms.filter(|&d| d > 0).map(|d| d.div_euclid(1000));

    // LINE's `chat_history` carries no direction column at all, so
    // `from_me` is never set and the record omits `is_from_me`/`direction`
    // rather than guessing from the sender mid. Attributing a message to the
    // wrong party is the most consequential error this tool can make.
    ChatMessage::new("LINE", "LINE", "Android")
        .text(content)
        .date_secs(date_s)
        .contact(from_mid)
        .chat_identifier(chat_id)
        .extra("rowid", json!(id))
        .into_artifact(case_id, parent_id)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod schema_golden_tests;
