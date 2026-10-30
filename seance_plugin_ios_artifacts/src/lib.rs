#![forbid(unsafe_code)]
//! Schema-aware parsers for iOS device databases that were previously only
//! raw-dumped as generic `SqliteRow`s. **Ten** ship:
//!
//! - **Voicemail** (`voicemail.db` → [`VoicemailParser`])
//! - **Calendar** (`Calendar.sqlitedb` → [`CalendarDbParser`]): timed events
//!   reuse the existing `CalendarEvent` viewer; Reminders (NULL-start
//!   `CalendarItem` rows) are emitted as `Reminder` records
//! - **Notes** (`NoteStore.sqlite` / `notes.sqlite` → [`NotesParser`]): title,
//!   snippet, the **body** (gzip-wrapped protobuf in `ZICNOTEDATA`, see
//!   [`notes_proto`]), folder, account and deletion state, plus one
//!   `NotesFolder` per folder and a `NotesSummary`
//! - **Photos catalog** (`Photos.sqlite` → [`PhotosParser`]): assets, and one
//!   `PhotoAlbum` per `ZGENERICALBUM` row with the album↔asset join table
//!   discovered from `Z_PRIMARYKEY` rather than named
//! - **`routined` location cache** (`Cache.sqlite` → [`RoutinedLocationParser`]):
//!   `ZRTCLLOCATIONMO` fixes with their accuracy, altitude, speed and course.
//!   `Cache.sqlite` is a name many apps use, so the **table** is what selects
//!   it, not the filename
//! - **PowerLog** (`CurrentPowerlog.PLSQL` and its rotated siblings →
//!   [`PowerLogParser`])
//! - **Safari bookmarks** (`Bookmarks.db` → [`SafariBookmarksParser`])
//! - **Safari open tabs** (`SafariTabs.db` on iOS 15+, `BrowserState.db` on
//!   iOS 13/14 → [`SafariTabsParser`]), with the private flag, the last
//!   visit to the microsecond and the tab's back/forward list
//! - **Safari recent searches** (`com.apple.mobilesafari.plist` →
//!   [`SafariSearchesParser`]), selected by the `RecentWebSearches` key
//! - **HealthKit** (`healthdb_secure.sqlite` → [`HealthKitParser`]), with the
//!   source name resolved from `healthdb.sqlite` beside it
//!
//! Each self-selects by basename + magic, probes its table/columns at
//! runtime, and never panics on an unexpected schema.
//!
//! **Not shipped, and why:** Voice Memos (`CloudRecordings.db`), voicemail
//! audio and transcripts, Photos faces, workouts and sleep samples, deleted
//! notes and note attachments have no instance in any iOS evidence this
//! project holds (the Magnet 2022 iOS 15 device never used Voice Memos, has
//! no voicemail, no faces, no workouts, no deleted notes). A reader written
//! from a specification alone would pass its own fixture and nothing else,
//! so where a table exists it is **counted and reported unread** rather than
//! decoded.
//!
//! This list was two parsers short of what the crate builds, which is
//! `DOC-023`: a crate doc is the first thing read before changing the crate,
//! and one that undercounts it invites a second implementation of a path that
//! already exists.

use std::collections::HashMap;

use rusqlite::Connection;
use seance_core::io::{is_sqlite_header, read_full, IncompleteReason};
use seance_core::time::{cocoa_secs_to_unix_nanos, unix_ns, unix_secs_f64_to_nanos, COCOA_EPOCH};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    probe_columns, probe_table, query_failed_marker, table_columns, unreadable_store_marker,
    Presence, RowDrops, TempDb,
};
use serde_json::{json, Value};
use uuid::Uuid;

mod health;
mod notes_attachments;
pub mod notes_proto;
mod safari;
mod voice_memos;
mod voicemail_files;
mod workouts;

pub use health::HealthKitParser;
pub use safari::{SafariBookmarksParser, SafariSearchesParser, SafariTabsParser};
pub use voice_memos::VoiceMemosParser;

const MAX_DB_BYTES: u64 = 1024 * 1024 * 1024;

fn basename(name: &str) -> String {
    name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase()
}

/// Common front end: gate an artifact by basename set + SQLite magic, spill to a
/// temp file, hand a read-only connection to `f`, then clean up.
///
/// The spill goes through [`TempDb::spill`], which compares what the source
/// delivered against what it declared. SQLite opens a truncated `voicemail.db`
/// / `Calendar.sqlitedb` / `NoteStore.sqlite` / `Photos.sqlite` / PowerLog and
/// answers from the pages it can still reach, so a partial staging produces a
/// partial recovery that looks exactly like a complete one. Every artifact `f`
/// produces is therefore stamped with `content_incomplete` /
/// `content_incomplete_reason` (and `wal_incomplete_reason` when the
/// uncheckpointed log could not be staged), plus one `parse_incomplete` marker
/// for the case where the truncation left nothing parsable at all (B3-012).
///
/// What an examiner learns: whether the voicemails, events, notes or photo
/// catalog entries listed are all of them. A wrong answer here is an absence
/// conclusion the evidence does not support.
///
/// The closure also receives the artifact's own data source, so a parser
/// whose store spans two files (HealthKit's `healthdb_secure.sqlite` and the
/// `healthdb.sqlite` beside it) can open the neighbour — and can tell a
/// source that cannot look from a neighbour that is not there.
fn with_db<F>(artifact: &Artifact, names: &[&str], tag: &str, f: F) -> Vec<Artifact>
where
    F: FnOnce(&Connection, &dyn DataSource, Uuid, Uuid) -> Vec<Artifact>,
{
    let name = artifact
        .metadata
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !names.contains(&basename(name).as_str()) {
        return Vec::new();
    }
    if artifact
        .metadata
        .get("is_directory")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return Vec::new();
    }
    let Some(data) = artifact.data.as_ref() else {
        return Vec::new();
    };
    // Probe the magic with a looping read: a windowed / container-backed source
    // may hand back fewer bytes than asked for, and a single short `read_at`
    // would file a real iOS database as "not SQLite".
    let mut head = [0u8; 16];
    let n = read_full(data.as_ref(), 0, &mut head);
    if !is_sqlite_header(&head[..n]) {
        return Vec::new();
    }
    // Spill with the `-wal` sibling: on a live-seized device the newest rows are
    // still only in the write-ahead log. `spill` also records whether the
    // database itself was staged in full.
    let temp = match TempDb::spill(data.as_ref(), &format!("ios_{tag}"), MAX_DB_BYTES) {
        Ok(t) => t,
        Err(e) => {
            // The name matched and the file really is SQLite: this is an iOS
            // database that could not be staged. Returning nothing reads as
            // "this device held no records of this kind", which is a claim
            // about the custodian nothing here established. The same defect
            // was found and fixed in the PST reader (B8-038) and in the
            // Timeline reader; this member of the class was missed.
            return vec![db_unusable_artifact(
                artifact.case_id,
                artifact.id,
                name,
                "database could not be staged for reading",
                &e.to_string(),
            )];
        }
    };
    let mut out = match temp.open() {
        Ok(conn) => f(&conn, data.as_ref(), artifact.case_id, artifact.id),
        Err(e) => vec![db_unusable_artifact(
            artifact.case_id,
            artifact.id,
            name,
            "staged database could not be opened",
            &e.to_string(),
        )],
    };
    // Stamp even when nothing parsed: "the database stopped being readable at
    // byte N" and "this device had no voicemails" must not render identically.
    temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
    out
}
/// The record that says a recognised iOS database could not be read at all.
///
/// Mirrors the `parse_incomplete` marker `TempDb::stamp_incompleteness`
/// appends, for the failures that happen before any row can be read — and
/// carries the same shape the Timeline and PST readers use, so a consumer
/// filtering for unreadable databases finds all of them.
fn db_unusable_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    what: &str,
    detail: &str,
) -> Artifact {
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("IosArtifactParseStatus"));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!("DatabaseUnreadable"));
    meta.insert("file_name".into(), json!(file_name));
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert(
        "content_incomplete_reason".into(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    meta.insert("inventory_incomplete".into(), json!(true));
    meta.insert(
        "inventory_incomplete_reason".into(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    meta.insert("records_recovered".into(), json!(0));
    meta.insert("detail".into(), json!(format!("{what}: {detail}")));
    meta.insert(
        "name".into(),
        json!(format!("{file_name}: iOS database unreadable — {what}")),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// The record that says a recognised iOS database was opened and the one
/// query a parser is built on did not run against it.
///
/// Every reader here is a fixed-column `SELECT` over a generation that was
/// held; on a generation that lacks a column the statement does not prepare.
/// Returning what had been collected so far — no records, no summary — read
/// as a device with no bookmarks, tabs or samples: the same absence
/// conclusion `db_unusable_artifact` exists to prevent, one step later.
fn query_unusable_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    query_over: &str,
    err: &rusqlite::Error,
) -> Artifact {
    db_unusable_artifact(
        case_id,
        parent_id,
        file_name,
        &format!("the {query_over} query this parser is built on did not run"),
        &err.to_string(),
    )
}

fn has_table(conn: &Connection, table: &str) -> bool {
    // Delegates so views count as present. A schema that exposes its rows
    // through a compatibility view -- recent `msgstore.db` generations keep
    // `messages` as one over the `message` table -- answered `type='table'`
    // with "no such table", and the walk that depends on it produced nothing
    // while the case read as a device with no records of this kind.
    matches!(probe_table(conn, table), Presence::Present)
}

/// The first of `tables` the store holds, or the records owed when it holds
/// none of them (HUNT-190).
///
/// `has_table` answers two questions with one `false`: "the catalogue was read
/// and the table is not in it" and "the catalogue would not read". A reader
/// that returned `Vec::new()` on that `false` rendered both as a device with no
/// voicemails, events, notes or photos. Here they are told apart:
///
/// * a catalogue that would not read is `DatabaseUnreadable`, naming SQLite's
///   error (when `claim_undetermined`);
/// * a readable catalogue holding none of the tables is `ExpectedTableAbsent`,
///   naming the tables looked for (when `claim_absent`): the store the name
///   identified is not in a schema this reader knows, so nothing was read from
///   it — which is not "the device held none".
///
/// A reader whose file name is shared with other apps (`Cache.sqlite`) passes
/// `false` for what it cannot claim, and keeps its silence there.
fn expected_table<'a>(
    conn: &Connection,
    case: Uuid,
    parent: Uuid,
    file_name: &str,
    tables: &[&'a str],
    claim_absent: bool,
    claim_undetermined: bool,
) -> Result<&'a str, Vec<Artifact>> {
    for table in tables {
        match probe_table(conn, table) {
            Presence::Present => return Ok(table),
            Presence::Absent => {}
            Presence::Undetermined(why) => {
                return Err(if claim_undetermined {
                    vec![db_unusable_artifact(
                        case,
                        parent,
                        file_name,
                        "the schema catalogue could not be read, so whether this store holds \
                         the table this reader is built on is undetermined",
                        &why,
                    )]
                } else {
                    Vec::new()
                });
            }
        }
    }
    if !claim_absent {
        return Err(Vec::new());
    }
    let listed = tables
        .iter()
        .map(|t| format!("`{t}`"))
        .collect::<Vec<_>>()
        .join(" or ");
    let detail = format!(
        "the schema catalogue was read and holds no {listed} table: this store is not in a \
         schema this reader knows, so no records were read from it — which is not a finding \
         that the device held none"
    );
    let unresolved = IncompleteReason::UnresolvedStructure.as_str();
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("IosArtifactParseStatus"));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!("ExpectedTableAbsent"));
    meta.insert("file_name".into(), json!(file_name));
    meta.insert("expected_tables".into(), json!(tables));
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert("content_incomplete_reason".into(), json!(unresolved));
    meta.insert("inventory_incomplete".into(), json!(true));
    meta.insert("inventory_incomplete_reason".into(), json!(unresolved));
    meta.insert("records_recovered".into(), json!(0));
    meta.insert("detail".into(), json!(detail));
    meta.insert(
        "name".into(),
        json!(format!("{file_name}: expected table absent — {listed}")),
    );
    Err(vec![Artifact::new(
        case,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent)
    .with_subtype("parse_incomplete")])
}

/// A SQLite boolean-ish INTEGER as JSON: `true`/`false` for a recorded value,
/// `null` for NULL. NULL is the column recording nothing, and writing it as
/// `false` asserted "not trashed" / "not a favourite" / "not all-day" from an
/// empty cell (HUNT-190).
fn flag_or_null(v: Option<i64>, set: impl Fn(i64) -> bool) -> Value {
    match v {
        Some(v) => json!(set(v)),
        None => Value::Null,
    }
}

// --- tolerant column readers -------------------------------------------------

fn cstr(r: &rusqlite::Row, idx: usize) -> Option<String> {
    seance_sqlite_util::row_text_present(r, idx)
}

fn cint(r: &rusqlite::Row, idx: usize) -> Option<i64> {
    seance_sqlite_util::row_i64(r, idx)
}

fn cfloat(r: &rusqlite::Row, idx: usize) -> Option<f64> {
    use rusqlite::types::ValueRef;
    match r.get_ref(idx).ok()? {
        ValueRef::Real(f) => Some(f),
        ValueRef::Integer(i) => Some(i as f64),
        _ => None,
    }
}

/// Map an iOS Photos `ZKIND` value to a media-kind label. Only the two values
/// documented in the Photos schema are trusted: 0 = photo, 1 = video. Any other
/// or missing value is reported as "unknown" rather than being silently
/// mislabelled a photo.
fn photos_media_kind(zkind: Option<i64>) -> &'static str {
    match zkind {
        Some(0) => "photo",
        Some(1) => "video",
        _ => "unknown",
    }
}

/// RFC3339 string for a Unix `(seconds, nanos)` instant.
///
/// The nanos are rendered rather than dropped: these strings are what the
/// calendar viewer and the reports show, so rounding them to the second would
/// contradict the `_ns` field published on the same record.
fn iso8601(unix: i64, nanos: u32) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix, nanos).map(|dt| dt.to_rfc3339())
}

/// Publish a decoded Cocoa instant on a record: the whole seconds under
/// `field`, and — only when the source recorded a fraction — the full-precision
/// Unix nanoseconds under `<field>_ns`.
///
/// Every one of these columns is REAL. Two events inside the same second are
/// ordered by the fraction alone, so a record carrying seconds only states an
/// ordering the evidence does not support.
fn insert_instant(m: &mut serde_json::Map<String, Value>, field: &str, secs: i64, nanos: u32) {
    m.insert(field.to_string(), json!(secs));
    if let Some(ns) = unix_ns(secs, nanos) {
        m.insert(format!("{field}_ns"), json!(ns));
    }
}

/// Publish a Cocoa REAL column as a Unix instant, naming the column and its
/// epoch beside it: `<field>`, `<field>_ns` when a fraction was recorded, and
/// `<field>_source` = "<column> (Apple Cocoa seconds since 2001-01-01,
/// converted to Unix)". Nothing is written for the 0/negative unset sentinel.
fn insert_cocoa(m: &mut serde_json::Map<String, Value>, field: &str, cocoa: f64, column: &str) {
    if let Some((secs, nanos)) = cocoa_secs_to_unix_nanos(cocoa) {
        insert_instant(m, field, secs, nanos);
        m.insert(
            format!("{field}_source"),
            json!(format!(
                "{column} (Apple Cocoa seconds since 2001-01-01, converted to Unix)"
            )),
        );
    }
}

fn parent_record(case_id: Uuid, parent_id: Uuid, meta: Value) -> Artifact {
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta).with_parent(parent_id)
}

// --- Voicemail ---------------------------------------------------------------

pub struct VoicemailParser;

impl ForensicsModule for VoicemailParser {
    fn id(&self) -> &str {
        "plugin.ios.voicemail"
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
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(with_db(
            artifact,
            &["voicemail.db"],
            "vm",
            |conn, ds, case, parent| {
                if let Err(owed) = expected_table(
                    conn,
                    case,
                    parent,
                    "voicemail.db",
                    &["voicemail"],
                    true,
                    true,
                ) {
                    return owed;
                }
                let mut stmt = match conn.prepare(
                    "SELECT ROWID, date, sender, callback_num, duration, trashed_date, receiver \
                 FROM voicemail ORDER BY date",
                ) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        return vec![query_unusable_artifact(
                            case,
                            parent,
                            "voicemail.db",
                            "voicemail",
                            &e,
                        )];
                    }
                };
                let rows = stmt.query_map([], |r| {
                    Ok((
                        cint(r, 0),
                        cint(r, 1),
                        cstr(r, 2),
                        cstr(r, 3),
                        cint(r, 4),
                        cint(r, 5),
                        cstr(r, 6),
                    ))
                });
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(e) => {
                        return vec![query_unusable_artifact(
                            case,
                            parent,
                            "voicemail.db",
                            "voicemail",
                            &e,
                        )];
                    }
                };
                let mut out = Vec::new();
                let mut drops = RowDrops::default();
                let mut files = voicemail_files::FileTally::default();
                let mut rowids = std::collections::BTreeSet::new();
                for row in rows {
                    let row = match row {
                        Ok(r) => r,
                        Err(e) => {
                            drops.record(&e);
                            continue;
                        }
                    };
                    let rowid = row.0;
                    let mut rec = voicemail_record(row, "voicemail");
                    if let (Some(id), Value::Object(m)) = (rowid, &mut rec) {
                        rowids.insert(id);
                        voicemail_files::attach(m, id, ds, &mut files);
                    }
                    out.push(parent_record(case, parent, rec));
                }
                let voicemails = out.len();
                let trashed = out
                    .iter()
                    .filter(|a| a.metadata["deleted"] == json!(true))
                    .count();
                if let Some(marker) =
                    drops.marker(case, parent, "VoicemailIncomplete", "voicemail", voicemails)
                {
                    out.push(marker);
                }
                // The count, zero included: a store that holds no voicemail
                // produced no record at all, which read exactly like a reader
                // that never ran (HUNT-215).
                let mut summary = json!({
                    "type": "VoicemailSummary",
                    "platform": "iOS",
                    "source": "voicemail.db",
                    "source_table": "voicemail",
                    "voicemails": voicemails,
                    "trashed": trashed,
                    "rows_undecodable": drops.dropped(),
                    "records_recovered": voicemails,
                    "name": format!(
                        "Voicemail store: {voicemails} voicemail(s), {trashed} trashed"
                    ),
                });
                // The `deleted` table (HUNT-233). The device held carries it
                // in its top-level store with the `voicemail` table's twelve
                // columns, and no row in it: what a row there means — a
                // voicemail deleted from the server, a tombstone — has never
                // been seen, so each is labelled by its table and unvalidated.
                match probe_table(conn, "deleted") {
                    Presence::Absent => {
                        summary["deleted_table_present"] = json!(false);
                    }
                    Presence::Undetermined(why) => {
                        mark_voicemail_deleted_unread(&mut summary, &why);
                    }
                    Presence::Present => {
                        summary["deleted_table_present"] = json!(true);
                        match read_voicemail_deleted_table(conn) {
                            Ok((rows, dropped)) => {
                                let n = rows.len();
                                for row in rows {
                                    if let Some(id) = row.0 {
                                        rowids.insert(id);
                                    }
                                    let mut m = voicemail_record(row, "deleted");
                                    m["row_semantics_validated"] = json!(false);
                                    out.push(parent_record(case, parent, m));
                                }
                                summary["deleted_table_rows"] = json!(n);
                                summary["deleted_table_rows_undecodable"] = json!(dropped);
                                summary["deleted_table_semantics_validated"] = json!(false);
                                summary["deleted_table_note"] = json!(
                                    "rows of the store's `deleted` table are read with the \
                                     `voicemail` table's column meanings; no device held has a \
                                     row there, so what a row records is not validated"
                                );
                                summary["records_recovered"] = json!(voicemails + n);
                                if dropped > 0 {
                                    summary["content_incomplete"] = json!(true);
                                    summary["content_incomplete_reason"] =
                                        json!(IncompleteReason::UnresolvedStructure.as_str());
                                    summary["content_incomplete_detail"] = json!(format!(
                                        "{dropped} row(s) of the `deleted` table would not \
                                         decode and are not in the case"
                                    ));
                                }
                            }
                            Err(why) => mark_voicemail_deleted_unread(&mut summary, &why),
                        }
                    }
                }
                // The audio and transcripts beside the store (§1.5).
                summary["audio_present"] = json!(files.audio_present);
                summary["audio_absent"] = json!(files.audio_absent);
                summary["transcripts_read"] = json!(files.transcripts_read);
                summary["transcripts_unread"] = json!(files.transcripts_unread);
                if files.unresolved > 0 {
                    summary["audio_unresolved"] = json!(files.unresolved);
                }
                // An audio file no row names. The directory must be listed to
                // find one; a source that cannot list says so.
                if drops.dropped() == 0 {
                    match voicemail_files::orphans(ds, &rowids) {
                        voicemail_files::Orphans::Listed(found) => {
                            summary["orphan_audio_files"] = json!(found.len());
                            for (file, id, size) in found {
                                out.push(parent_record(
                                    case,
                                    parent,
                                    json!({
                                        "type": "VoicemailAudioOrphan",
                                        "subtype": "voicemail_audio_orphan",
                                        "platform": "iOS",
                                        "audio_file": file,
                                        "audio_bytes": size,
                                        "implied_rowid": id,
                                        "deleted_row_inferred": false,
                                        "detail": "an audio file beside voicemail.db that no row of the \
                                                   store's voicemail or deleted table names; a voicemail \
                                                   whose row is gone is the natural reading, and is not \
                                                   asserted",
                                        "name": format!("Voicemail audio with no row: {file}"),
                                    }),
                                ));
                            }
                        }
                        voicemail_files::Orphans::CannotList => {
                            summary["orphan_audio_files_unresolved"] = json!(true);
                        }
                    }
                } else {
                    // A row that would not decode may name any file: an
                    // orphan claim would be unfounded.
                    summary["orphan_audio_files_unresolved"] = json!(true);
                }
                out.push(parent_record(case, parent, summary));
                out
            },
        ))
    }
}

/// One voicemail-store row: `ROWID, date, sender, callback_num, duration,
/// trashed_date, receiver`.
type VoicemailRow = (
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

/// The record for one row of `table` (`voicemail` or `deleted`).
fn voicemail_record(row: VoicemailRow, table: &str) -> Value {
    let (rowid, date, sender, cb, dur, trashed, receiver) = row;
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("Voicemail"));
    m.insert("subtype".into(), json!("voicemail"));
    m.insert("platform".into(), json!("iOS"));
    m.insert("source_table".into(), json!(table));
    if let Some(r) = rowid {
        m.insert("rowid".into(), json!(r));
    }
    // voicemail.db `date` is already Unix seconds.
    if let Some(d) = date.filter(|&d| d > 0) {
        m.insert("date".into(), json!(d));
    }
    if let Some(s) = &sender {
        m.insert("sender".into(), json!(s));
        m.insert("contact".into(), json!(s));
    }
    if let Some(c) = cb {
        m.insert("callback_number".into(), json!(c));
    }
    if let Some(d) = dur {
        m.insert("duration_seconds".into(), json!(d));
    }
    if let Some(r) = receiver {
        m.insert("receiver".into(), json!(r));
    }
    // `trashed_date` 0 is "not trashed"; NULL is unknown.
    m.insert("deleted".into(), flag_or_null(trashed, |t| t > 0));
    m.insert(
        "name".into(),
        json!(format!(
            "Voicemail from {}",
            sender.as_deref().unwrap_or("unknown")
        )),
    );
    Value::Object(m)
}

/// Every row of the voicemail store's `deleted` table, with the count that
/// would not decode. A column the table lacks reads as NULL; `Err` is a table
/// whose rows could not be walked at all.
fn read_voicemail_deleted_table(conn: &Connection) -> Result<(Vec<VoicemailRow>, usize), String> {
    let cols = table_columns(conn, "deleted");
    let col = |c: &'static str| if cols.contains(c) { c } else { "NULL" };
    let sql = format!(
        "SELECT ROWID, {}, {}, {}, {}, {}, {} FROM deleted ORDER BY ROWID",
        col("date"),
        col("sender"),
        col("callback_num"),
        col("duration"),
        col("trashed_date"),
        col("receiver"),
    );
    let failed = |e: rusqlite::Error| format!("`deleted` would not read: {e}");
    let mut stmt = conn.prepare(&sql).map_err(failed)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                cint(r, 0),
                cint(r, 1),
                cstr(r, 2),
                cstr(r, 3),
                cint(r, 4),
                cint(r, 5),
                cstr(r, 6),
            ))
        })
        .map_err(failed)?;
    let mut out = Vec::new();
    let mut dropped = 0usize;
    for row in rows {
        match row {
            Ok(r) => out.push(r),
            Err(_) => dropped += 1,
        }
    }
    Ok((out, dropped))
}

/// The `deleted` table is there (or may be) and was not read: a
/// could-not-look, never a count of zero.
fn mark_voicemail_deleted_unread(summary: &mut Value, why: &str) {
    summary["deleted_table_unread"] = json!(true);
    summary["content_incomplete"] = json!(true);
    summary["content_incomplete_reason"] = json!(IncompleteReason::UnresolvedStructure.as_str());
    summary["content_incomplete_detail"] = json!(format!(
        "the store's `deleted` table could not be read, so any voicemail rows it holds are not \
         in the case: {why}"
    ));
}

// --- Calendar (Calendar.sqlitedb) -------------------------------------------

pub struct CalendarDbParser;

impl ForensicsModule for CalendarDbParser {
    fn id(&self) -> &str {
        "plugin.ios.calendar_db"
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
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(with_db(
            artifact,
            &["calendar.sqlitedb"],
            "cal",
            |conn, _ds, case, parent| {
                if let Err(owed) = expected_table(
                    conn,
                    case,
                    parent,
                    "Calendar.sqlitedb",
                    &["CalendarItem"],
                    true,
                    true,
                ) {
                    return owed;
                }
                let mut stmt = match conn.prepare(
                    "SELECT ci.summary, ci.description, ci.start_date, ci.end_date, \
                            ci.all_day, c.title \
                     FROM CalendarItem ci LEFT JOIN Calendar c ON c.ROWID = ci.calendar_id \
                     ORDER BY ci.start_date",
                ) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        return vec![query_unusable_artifact(
                            case,
                            parent,
                            "Calendar.sqlitedb",
                            "CalendarItem",
                            &e,
                        )];
                    }
                };
                let rows = stmt.query_map([], |r| {
                    Ok((
                        cstr(r, 0),
                        cstr(r, 1),
                        cfloat(r, 2),
                        cfloat(r, 3),
                        cint(r, 4),
                        cstr(r, 5),
                    ))
                });
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(e) => {
                        return vec![query_unusable_artifact(
                            case,
                            parent,
                            "Calendar.sqlitedb",
                            "CalendarItem",
                            &e,
                        )];
                    }
                };
                let mut out = Vec::new();
                let mut drops = RowDrops::default();
                for row in rows {
                    let (summary, desc, start, end, all_day, cal) = match row {
                        Ok(r) => r,
                        Err(e) => {
                            drops.record(&e);
                            continue;
                        }
                    };
                    // Reminders share this table as NULL-`start_date` rows; they
                    // are emitted separately as `Reminder` records below.
                    if start.is_none() {
                        continue;
                    }
                    // Emit the same shape as the iCal parser so the existing
                    // CalendarEvent viewer renders these too.
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), json!("CalendarEvent"));
                    m.insert("subtype".into(), json!("calendar_event"));
                    m.insert("source".into(), json!("Calendar.sqlitedb"));
                    if let Some(s) = summary {
                        m.insert("summary".into(), json!(s));
                    }
                    if let Some(d) = desc {
                        m.insert("description".into(), json!(d));
                    }
                    if let Some(c) = cal {
                        m.insert("calendar_name".into(), json!(c));
                    }
                    m.insert("all_day".into(), flag_or_null(all_day, |v| v != 0));
                    if let Some((secs, nanos)) = start.and_then(cocoa_secs_to_unix_nanos) {
                        if let Some(iso) = iso8601(secs, nanos) {
                            m.insert("dtstart".into(), json!(iso));
                        }
                        insert_instant(&mut m, "date", secs, nanos);
                    }
                    if let Some((secs, nanos)) = end.and_then(cocoa_secs_to_unix_nanos) {
                        if let Some(iso) = iso8601(secs, nanos) {
                            m.insert("dtend".into(), json!(iso));
                        }
                    }
                    out.push(parent_record(case, parent, Value::Object(m)));
                }
                let events = out.len();
                if let Some(marker) = drops.marker(
                    case,
                    parent,
                    "CalendarEventIncomplete",
                    "CalendarItem",
                    events,
                ) {
                    out.push(marker);
                }
                let (reminder_records, reminders) = calendar_reminders(conn, case, parent);
                out.extend(reminder_records);
                // The counts, zeros included: a present, empty `CalendarItem`
                // produced no record at all (HUNT-215). A reminders query that
                // did not run is `null` here, never 0; its own record says why.
                out.push(parent_record(
                    case,
                    parent,
                    json!({
                        "type": "CalendarSummary",
                        "platform": "iOS",
                        "source": "Calendar.sqlitedb",
                        "source_table": "CalendarItem",
                        "events": events,
                        "event_rows_undecodable": drops.dropped(),
                        "reminders": reminders,
                        "reminders_status": if reminders.is_some() { "read" } else { "query_did_not_run" },
                        "records_recovered": events + reminders.unwrap_or(0),
                        "name": match reminders {
                            Some(r) => format!("Calendar store: {events} event(s), {r} reminder(s)"),
                            None => format!("Calendar store: {events} event(s), reminders not read"),
                        },
                    }),
                ));
                out
            },
        ))
    }
}

/// Reminders live in the same `Calendar.sqlitedb` as events: a reminder is a
/// `CalendarItem` row with no `start_date` (NULL) that instead carries a
/// `due_date`, `completion_date`, and `priority`. Emitted as `Reminder` records
/// so to-dos render distinctly from timed events.
///
/// The column is `completion_date` on the one real store held (the Magnet 2022
/// iPhone 8, iOS 15); this reader asked for `completed_date`, so the statement
/// never prepared on a real device. Returns the records and the reminder
/// count, or `None` when the query did not run — which is a
/// `ReminderIncomplete` `DatabaseUnreadable` record naming SQLite's error,
/// never "no reminders" (HUNT-213).
fn calendar_reminders(
    conn: &Connection,
    case: Uuid,
    parent: Uuid,
) -> (Vec<Artifact>, Option<usize>) {
    // The events query has just read `CalendarItem`, so its column list reading
    // is expected; `query_failed_marker` says the columns were read, and this
    // keeps that sentence true.
    if let Err(why) = probe_columns(conn, "CalendarItem") {
        return (
            vec![unreadable_store_marker(
                case,
                parent,
                "ReminderIncomplete",
                format!(
                    "the `CalendarItem` column list would not read, so no reminder was \
                     looked for: {why}"
                ),
            )],
            None,
        );
    }
    let query_failed = |e: rusqlite::Error| {
        (
            vec![query_failed_marker(
                case,
                parent,
                "ReminderIncomplete",
                "CalendarItem",
                &e.to_string(),
            )],
            None,
        )
    };
    let mut stmt = match conn.prepare(
        "SELECT ci.summary, ci.due_date, ci.completion_date, ci.priority, c.title \
         FROM CalendarItem ci LEFT JOIN Calendar c ON c.ROWID = ci.calendar_id \
         WHERE ci.start_date IS NULL \
         ORDER BY ci.due_date",
    ) {
        Ok(stmt) => stmt,
        Err(e) => return query_failed(e),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            cstr(r, 0),
            cfloat(r, 1),
            cfloat(r, 2),
            cint(r, 3),
            cstr(r, 4),
        ))
    });
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => return query_failed(e),
    };
    let mut out = Vec::new();
    let mut drops = RowDrops::default();
    for row in rows {
        let (summary, due, completed_date, priority, cal) = match row {
            Ok(r) => r,
            Err(e) => {
                drops.record(&e);
                continue;
            }
        };
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("Reminder"));
        m.insert("subtype".into(), json!("reminder"));
        m.insert("source".into(), json!("Calendar.sqlitedb"));
        let title = summary.unwrap_or_else(|| "Reminder".into());
        m.insert("title".into(), json!(title));
        // Omit an unset due date rather than fabricating the 2001 epoch.
        if let Some((secs, nanos)) = due.and_then(cocoa_secs_to_unix_nanos) {
            insert_instant(&mut m, "due", secs, nanos);
        }
        // A reminder is complete iff it has a real (positive) completion date.
        // A raw 0.0 in ZCOMPLETIONDATE is "not completed", so key off the decoded
        // value rather than the presence of the raw column.
        let completed = completed_date.and_then(cocoa_secs_to_unix_nanos);
        m.insert("completed".into(), json!(completed.is_some()));
        if let Some((secs, nanos)) = completed {
            insert_instant(&mut m, "completed_date", secs, nanos);
        }
        // iOS uses priority 0 to mean "none"; only surface a real priority.
        if let Some(p) = priority.filter(|&p| p != 0) {
            m.insert("priority".into(), json!(p));
        }
        if let Some(c) = cal {
            m.insert("calendar_name".into(), json!(c));
        }
        m.insert("name".into(), json!(title));
        out.push(parent_record(case, parent, Value::Object(m)));
    }
    let reminders = out.len();
    if let Some(marker) = drops.marker(
        case,
        parent,
        "ReminderIncomplete",
        "CalendarItem",
        reminders,
    ) {
        out.push(marker);
    }
    (out, Some(reminders))
}

// --- Notes (NoteStore.sqlite / notes.sqlite) --------------------------------

/// Where the phone was, from the location cache the system keeps for itself.
///
/// `com.apple.routined`'s `Cache.sqlite` holds `ZRTCLLOCATIONMO`: every fix
/// CoreLocation recorded, with its accuracy, altitude, speed and course. It is
/// the answer to the question asked of a phone more often than any other —
/// **where was this device, and when** — and it survives app deletions and
/// history clearing because nothing about it belongs to an app (`HUNT-099`).
///
/// Two of CoreLocation's conventions are honoured rather than copied:
///
/// * a **negative horizontal accuracy** is how CoreLocation says the fix is
///   invalid. Such a row usually carries 0,0, and drawing it would put the
///   phone in the Gulf of Guinea; it is counted and left off the map.
/// * **-1 speed and -1 course** mean *not measured*. They are absent from the
///   record rather than reported as a phone travelling backwards at one metre
///   per second.
pub struct RoutinedLocationParser;

/// Ceiling on fixes carried into one case from a single cache.
const MAX_LOCATION_FIXES: usize = 200_000;

impl ForensicsModule for RoutinedLocationParser {
    fn id(&self) -> &str {
        "plugin.ios.routined_locations"
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
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // `Cache.sqlite` is a name many apps use, so the name alone claims
        // nothing. Only one at `com.apple.routined`'s own path is the location
        // cache by where it lives, and a catalogue there that will not read is
        // the location history unread (HUNT-190).
        let at_routined_path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .is_some_and(|p| p.to_ascii_lowercase().contains("com.apple.routined"));
        Ok(with_db(
            artifact,
            &["cache.sqlite"],
            "routined",
            |conn, _ds, case, parent| {
                // The table is what makes this the location cache; a readable
                // catalogue without it is another app's database.
                if let Err(owed) = expected_table(
                    conn,
                    case,
                    parent,
                    "Cache.sqlite",
                    &["ZRTCLLOCATIONMO"],
                    false,
                    at_routined_path,
                ) {
                    return owed;
                }
                let mut stmt = match conn.prepare(
                    "SELECT ZLATITUDE, ZLONGITUDE, ZTIMESTAMP, ZHORIZONTALACCURACY, \
                            ZVERTICALACCURACY, ZALTITUDE, ZSPEED, ZCOURSE \
                     FROM ZRTCLLOCATIONMO ORDER BY ZTIMESTAMP DESC LIMIT ?1",
                ) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        return vec![query_unusable_artifact(
                            case,
                            parent,
                            "Cache.sqlite",
                            "ZRTCLLOCATIONMO",
                            &e,
                        )];
                    }
                };
                let rows = stmt.query_map([MAX_LOCATION_FIXES as i64 + 1], |r| {
                    Ok((
                        cfloat(r, 0),
                        cfloat(r, 1),
                        cfloat(r, 2),
                        cfloat(r, 3),
                        cfloat(r, 4),
                        cfloat(r, 5),
                        cfloat(r, 6),
                        cfloat(r, 7),
                    ))
                });
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(e) => {
                        return vec![query_unusable_artifact(
                            case,
                            parent,
                            "Cache.sqlite",
                            "ZRTCLLOCATIONMO",
                            &e,
                        )];
                    }
                };

                let mut out = Vec::new();
                let mut fixes = 0usize;
                let mut invalid = 0usize;
                let mut undecodable = 0usize;
                for row in rows {
                    let Ok((lat, lon, ts, h_acc, v_acc, alt, speed, course)) = row else {
                        undecodable += 1;
                        continue;
                    };
                    let (Some(lat), Some(lon)) = (lat, lon) else {
                        undecodable += 1;
                        continue;
                    };
                    // CoreLocation's own invalidity flag.
                    if h_acc.is_some_and(|a| a < 0.0) {
                        invalid += 1;
                        continue;
                    }
                    fixes += 1;
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), json!("CachedLocation"));
                    m.insert("platform".into(), json!("iOS"));
                    m.insert("source".into(), json!("com.apple.routined"));
                    // The keys the map screen reads.
                    m.insert("gps_lat".into(), json!(lat));
                    m.insert("gps_lon".into(), json!(lon));
                    if let Some((secs, nanos)) = ts.and_then(cocoa_secs_to_unix_nanos) {
                        if let Some(dt) = chrono::DateTime::from_timestamp(secs, nanos) {
                            m.insert("timestamp".into(), json!(dt.to_rfc3339()));
                        }
                    }
                    if let Some(a) = h_acc {
                        m.insert("horizontal_accuracy_m".into(), json!(a));
                    }
                    if let Some(a) = v_acc.filter(|a| *a >= 0.0) {
                        m.insert("vertical_accuracy_m".into(), json!(a));
                    }
                    if let Some(a) = alt.filter(|a| *a != 0.0) {
                        m.insert("altitude_m".into(), json!(a));
                    }
                    // -1 is "not measured", not a measurement.
                    if let Some(s) = speed.filter(|s| *s >= 0.0) {
                        m.insert("speed_mps".into(), json!(s));
                    }
                    if let Some(c) = course.filter(|c| *c >= 0.0) {
                        m.insert("course_deg".into(), json!(c));
                    }
                    m.insert("name".into(), json!(format!("{lat:.6}, {lon:.6}")));
                    out.push(
                        Artifact::new(
                            case,
                            ArtifactType::ParsedRecord,
                            None,
                            serde_json::Value::Object(m),
                        )
                        .with_parent(parent),
                    );
                }

                let capped = fixes > MAX_LOCATION_FIXES;
                out.truncate(MAX_LOCATION_FIXES);
                // What the cache held, beside what reached the map. A location
                // list presented as whole when rows were dropped is the one
                // shape an examiner cannot check by looking.
                let mut summary = serde_json::Map::new();
                summary.insert("type".into(), json!("CachedLocationSummary"));
                summary.insert("platform".into(), json!("iOS"));
                summary.insert("source".into(), json!("com.apple.routined"));
                summary.insert(
                    "name".into(),
                    json!(format!("Cached locations: {fixes} fix(es)")),
                );
                summary.insert("fixes".into(), json!(fixes.min(MAX_LOCATION_FIXES)));
                summary.insert("invalid_fixes".into(), json!(invalid));
                summary.insert("undecodable_rows".into(), json!(undecodable));
                if capped || undecodable > 0 {
                    summary.insert("inventory_incomplete".into(), json!(true));
                    summary.insert(
                        "inventory_incomplete_reason".into(),
                        json!(if capped {
                            IncompleteReason::CapReached.as_str()
                        } else {
                            IncompleteReason::UnresolvedStructure.as_str()
                        }),
                    );
                    summary.insert(
                        "inventory_incomplete_detail".into(),
                        json!(if capped {
                            format!(
                                "more than {MAX_LOCATION_FIXES} fixes are in this cache; the \
                                 list stops there and the older ones are not in this case"
                            )
                        } else {
                            format!("{undecodable} row(s) in the location cache could not be read")
                        }),
                    );
                }
                out.push(
                    Artifact::new(
                        case,
                        ArtifactType::ParsedRecord,
                        None,
                        serde_json::Value::Object(summary),
                    )
                    .with_parent(parent),
                );
                out
            },
        ))
    }
}

pub struct NotesParser;

/// Ceiling on notes carried into one case from a single store.
const MAX_NOTES: usize = 200_000;

/// `Z_PRIMARYKEY.Z_SUPER`: each entity's parent entity, for the ones that
/// have one. A relationship table belongs to the entity that declares it
/// and to every entity that descends from it — Core Data keeps a
/// `CloudSharedAlbum`'s memberships in `Album`'s `Z_27ASSETS`, not in a
/// table of its own — so "is this entity an Album" is a walk up this map.
///
/// `Err` is "could not look": the table's presence could not be established,
/// or its statement would not prepare, run or finish. An absent table is
/// `Ok(empty)` — a store shape, not a failure. The rows used to be read with
/// `if let Ok` and `.flatten()`, so a damaged `Z_PRIMARYKEY` became an empty
/// map and every album count built on it became "unresolved" or zero with
/// nothing to say a query had failed (HUNT-214).
fn core_data_supers(conn: &Connection) -> Result<HashMap<i64, i64>, String> {
    let mut out = HashMap::new();
    for (e, sup) in z_primarykey_pairs(conn, "Z_SUPER", |r| Ok((cint(r, 0), cint(r, 1))))? {
        if let (Some(e), Some(sup)) = (e, sup) {
            if sup > 0 {
                out.insert(e, sup);
            }
        }
    }
    Ok(out)
}

/// Every `(Z_ENT, <column>)` row of `Z_PRIMARYKEY`, read to the end or not at
/// all: a row that fails mid-walk fails the lookup, never shortens it.
fn z_primarykey_pairs<T>(
    conn: &Connection,
    column: &str,
    row: impl FnMut(&rusqlite::Row) -> rusqlite::Result<T>,
) -> Result<Vec<T>, String> {
    match probe_table(conn, "Z_PRIMARYKEY") {
        Presence::Present => {}
        Presence::Absent => return Ok(Vec::new()),
        Presence::Undetermined(why) => return Err(why),
    }
    let sql = if column == "Z_NAME" {
        "SELECT Z_NAME, Z_ENT FROM Z_PRIMARYKEY"
    } else {
        "SELECT Z_ENT, Z_SUPER FROM Z_PRIMARYKEY"
    };
    let failed = |e: rusqlite::Error| format!("`Z_PRIMARYKEY` ({column}) would not read: {e}");
    let mut stmt = conn.prepare(sql).map_err(failed)?;
    let rows = stmt.query_map([], row).map_err(failed)?;
    rows.collect::<rusqlite::Result<Vec<T>>>().map_err(failed)
}

/// Whether `ent` is `root` or descends from it through `Z_SUPER`. Bounded so
/// a cyclic table cannot loop.
fn descends_from(supers: &HashMap<i64, i64>, ent: i64, root: i64) -> bool {
    let mut cur = ent;
    for _ in 0..32 {
        if cur == root {
            return true;
        }
        match supers.get(&cur) {
            Some(&next) => cur = next,
            None => return false,
        }
    }
    false
}

/// `Z_PRIMARYKEY`: Core Data's entity table, name → `Z_ENT`. `Err` is "could
/// not look" (see [`core_data_supers`]); an absent table is `Ok(empty)`.
fn core_data_entities(conn: &Connection) -> Result<HashMap<String, i64>, String> {
    let mut out = HashMap::new();
    for (n, e) in z_primarykey_pairs(conn, "Z_NAME", |r| Ok((cstr(r, 0), cint(r, 1))))? {
        if let (Some(n), Some(e)) = (n, e) {
            out.insert(n, e);
        }
    }
    Ok(out)
}

/// Row count of `table`: `Ok(None)` is absent, `Err` is a table whose
/// presence or count could not be read. The two-answer `table_count` this
/// replaced returned `None` for both, and its callers published a count that
/// failed as an absent table or as zero rows (HUNT-238).
fn table_count_checked(conn: &Connection, table: &str) -> Result<Option<i64>, String> {
    match probe_table(conn, table) {
        Presence::Present => {}
        Presence::Absent => return Ok(None),
        Presence::Undetermined(why) => return Err(why),
    }
    conn.query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| {
        r.get(0)
    })
    .map(Some)
    .map_err(|e| format!("`{table}` would not count: {e}"))
}

struct NoteFolder {
    title: Option<String>,
    folder_type: Option<i64>,
}

/// Every row `sql` yields, up to the first that fails, and that failure.
///
/// Rows read before a failure are real and kept; the ones after it were never
/// seen, which the failure says. The Notes folder and account lookups used to
/// be read with `if let Ok` and `.flatten()`, so a lookup that failed left
/// notes with no folder and no account and nothing to say it had not been
/// looked up (HUNT-232, the class HUNT-214 fixed for Photos).
fn rows_until_failure<T>(
    conn: &Connection,
    sql: &str,
    row: impl FnMut(&rusqlite::Row) -> rusqlite::Result<T>,
) -> (Vec<T>, Option<String>) {
    let mut stmt = match conn.prepare(sql) {
        Ok(stmt) => stmt,
        Err(e) => return (Vec::new(), Some(e.to_string())),
    };
    let rows = match stmt.query_map([], row) {
        Ok(rows) => rows,
        Err(e) => return (Vec::new(), Some(e.to_string())),
    };
    let mut out = Vec::new();
    for r in rows {
        match r {
            Ok(v) => out.push(v),
            Err(e) => return (out, Some(e.to_string())),
        }
    }
    (out, None)
}

impl ForensicsModule for NotesParser {
    fn id(&self) -> &str {
        "plugin.ios.notes"
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
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // The store goes by two names; a marker names the one this file has.
        let file_name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .map(|n| n.rsplit('/').next().unwrap_or(n).to_string())
            .unwrap_or_else(|| "NoteStore.sqlite".to_string());
        Ok(with_db(
            artifact,
            &["notestore.sqlite", "notes.sqlite"],
            "notes",
            |conn, ds, case, parent| {
                // Modern Notes (iOS 9+): ZICCLOUDSYNCINGOBJECT with ZTITLE1/ZSNIPPET.
                if let Err(owed) = expected_table(
                    conn,
                    case,
                    parent,
                    &file_name,
                    &["ZICCLOUDSYNCINGOBJECT"],
                    true,
                    true,
                ) {
                    return owed;
                }
                let cols = table_columns(conn, "ZICCLOUDSYNCINGOBJECT");
                let has = |c: &str| cols.contains(&c.to_ascii_lowercase());
                // A failed entity lookup falls back to the title heuristic,
                // which `entity_resolution` on the summary names — and, being
                // a could-not-look, is a lookup failure too: without the
                // entity numbers no folder or account can be read (HUNT-232).
                let mut lookup_failures: Vec<String> = Vec::new();
                let entities = match core_data_entities(conn) {
                    Ok(entities) => entities,
                    Err(why) => {
                        lookup_failures.push(format!("Core Data entity names: {why}"));
                        HashMap::new()
                    }
                };
                let entities_failed = !lookup_failures.is_empty();
                let note_ent = entities.get("ICNote").copied();
                let folder_ent = entities.get("ICFolder").copied();
                let account_ent = entities.get("ICAccount").copied();
                let attachment_ent = entities.get("ICAttachment").copied();

                // The note rows are selected by entity when the file says
                // which entity a note is; a store without `Z_PRIMARYKEY` (or
                // without `Z_ENT`) falls back to "has a title", and says so.
                let (note_filter, entity_resolution) = match note_ent {
                    Some(e) if has("Z_ENT") => (format!("Z_ENT = {e}"), "z_primarykey"),
                    _ => ("ZTITLE1 IS NOT NULL".to_string(), "title_heuristic"),
                };

                // Folders and accounts, for the note's folder title and
                // account, and as records of their own.
                let mut folders: HashMap<i64, NoteFolder> = HashMap::new();
                let mut accounts: HashMap<i64, String> = HashMap::new();
                let mut out = Vec::new();
                // Whether a note with no folder or account resolved could not
                // be looked up, rather than has none.
                let mut accounts_failed = entities_failed;
                let mut folders_failed = entities_failed;
                if let (Some(ae), true, true) = (account_ent, has("Z_ENT"), has("ZIDENTIFIER")) {
                    let sql = format!(
                        "SELECT Z_PK, ZIDENTIFIER FROM ZICCLOUDSYNCINGOBJECT WHERE Z_ENT = {ae}"
                    );
                    let (rows, failed) =
                        rows_until_failure(conn, &sql, |r| Ok((cint(r, 0), cstr(r, 1))));
                    for row in rows {
                        if let (Some(pk), Some(id)) = row {
                            accounts.insert(pk, id);
                        }
                    }
                    if let Some(why) = failed {
                        lookup_failures.push(format!("accounts (ICAccount rows): {why}"));
                        accounts_failed = true;
                    }
                }

                // Core Data flattens every subclass's `account` relationship
                // into its own column — `ZACCOUNT4` for a note and
                // `ZACCOUNT5` for a folder on the device held, and other
                // numbers on other releases — so the link is resolved from
                // whichever `ZACCOUNT*` column names an account row.
                let mut account_cols: Vec<String> = cols
                    .iter()
                    .filter(|c| {
                        c.starts_with("zaccount") && c[8..].chars().all(|ch| ch.is_ascii_digit())
                    })
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                account_cols.sort();
                let account_select = if account_cols.is_empty() {
                    "NULL".to_string()
                } else {
                    account_cols.join(", ")
                };
                let n_account_cols = account_cols.len().max(1);
                let resolve_account = |r: &rusqlite::Row, first: usize| {
                    (0..n_account_cols)
                        .filter_map(|i| cint(r, first + i))
                        .find(|a| accounts.contains_key(a))
                };
                if let (Some(fe), true, true) = (folder_ent, has("Z_ENT"), has("ZTITLE2")) {
                    let ft = if has("ZFOLDERTYPE") {
                        "ZFOLDERTYPE"
                    } else {
                        "NULL"
                    };
                    let ident = if has("ZIDENTIFIER") {
                        "ZIDENTIFIER"
                    } else {
                        "NULL"
                    };
                    let sql = format!(
                        "SELECT Z_PK, ZTITLE2, {ft}, {ident}, {account_select} FROM ZICCLOUDSYNCINGOBJECT WHERE Z_ENT = {fe} ORDER BY Z_PK"
                    );
                    let (rows, failed) = rows_until_failure(conn, &sql, |r| {
                        Ok((
                            cint(r, 0),
                            cstr(r, 1),
                            cint(r, 2),
                            cstr(r, 3),
                            resolve_account(r, 4),
                        ))
                    });
                    if let Some(why) = failed {
                        lookup_failures.push(format!("folders (ICFolder rows): {why}"));
                        folders_failed = true;
                    }
                    {
                        {
                            for row in rows {
                                let (Some(pk), title, ftype, ident, acct) = row else {
                                    continue;
                                };
                                folders.insert(
                                    pk,
                                    NoteFolder {
                                        title: title.clone(),
                                        folder_type: ftype,
                                    },
                                );
                                let mut m = serde_json::Map::new();
                                m.insert("type".into(), json!("NotesFolder"));
                                m.insert("subtype".into(), json!("notes_folder"));
                                m.insert("platform".into(), json!("iOS"));
                                m.insert("folder_id".into(), json!(pk));
                                if let Some(t) = &title {
                                    m.insert("title".into(), json!(t));
                                }
                                if let Some(ft) = ftype {
                                    m.insert("folder_type".into(), json!(ft));
                                    // ZFOLDERTYPE 1 is the Recently Deleted
                                    // folder on the device held (both of its
                                    // "Recently Deleted" rows carry it, the
                                    // two "Notes" rows carry 0).
                                    m.insert("is_trash".into(), json!(ft == 1));
                                    m.insert(
                                        "is_trash_basis".into(),
                                        json!("ZFOLDERTYPE = 1, as the Recently Deleted folders of the device held carry"),
                                    );
                                }
                                if let Some(i) = ident {
                                    m.insert("identifier".into(), json!(i));
                                }
                                if let Some(a) = acct {
                                    m.insert("account_id".into(), json!(a));
                                    if let Some(name) = accounts.get(&a) {
                                        m.insert("account".into(), json!(name));
                                    }
                                }
                                m.insert(
                                    "name".into(),
                                    json!(format!(
                                        "Notes folder: {}",
                                        title.as_deref().unwrap_or("(untitled)")
                                    )),
                                );
                                out.push(parent_record(case, parent, Value::Object(m)));
                            }
                        }
                    }
                }
                // Bodies, keyed by note. A `ZICNOTEDATA` that is there but
                // whose statement does not run leaves every body unread,
                // which is said on the note; it is not a note with no body.
                let has_note_data = has_table(conn, "ZICNOTEDATA");
                let mut bodies: HashMap<i64, (Vec<u8>, bool)> = HashMap::new();
                let bodies_read: Option<rusqlite::Result<()>> = has_note_data.then(|| {
                    let dcols = table_columns(conn, "ZICNOTEDATA");
                    let tag = if dcols.contains("zcryptotag") {
                        "ZCRYPTOTAG IS NOT NULL"
                    } else {
                        "0"
                    };
                    let sql = format!("SELECT ZNOTE, ZDATA, {tag} FROM ZICNOTEDATA");
                    let mut stmt = conn.prepare(&sql)?;
                    let iter = stmt.query_map([], |r| {
                        Ok((cint(r, 0), r.get::<_, Vec<u8>>(1).ok(), cint(r, 2)))
                    })?;
                    for row in iter.flatten() {
                        if let (Some(n), Some(d), enc) = row {
                            bodies.insert(n, (d, enc.unwrap_or(0) != 0));
                        }
                    }
                    Ok(())
                });
                let body_query_error: Option<String> = match &bodies_read {
                    Some(Err(e)) => Some(e.to_string()),
                    _ => None,
                };

                let opt = |c: &str| {
                    if has(c) {
                        c.to_string()
                    } else {
                        "NULL".to_string()
                    }
                };
                let sql = format!(
                    "SELECT Z_PK, ZTITLE1, ZSNIPPET, ZCREATIONDATE, ZMODIFICATIONDATE, {}, {}, {}, {}, {} \
                     FROM ZICCLOUDSYNCINGOBJECT WHERE {note_filter} \
                     ORDER BY ZMODIFICATIONDATE DESC LIMIT {}",
                    opt("ZFOLDER"),
                    opt("ZMARKEDFORDELETION"),
                    opt("ZIDENTIFIER"),
                    opt("ZISPASSWORDPROTECTED"),
                    account_select,
                    MAX_NOTES + 1
                );
                // The folder and account records collected so far are kept:
                // they were read. The note walk was not, and the marker says
                // so in place of a summary that would have counted nothing.
                let mut stmt = match conn.prepare(&sql) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        out.push(query_unusable_artifact(
                            case,
                            parent,
                            &file_name,
                            "ZICCLOUDSYNCINGOBJECT note",
                            &e,
                        ));
                        return out;
                    }
                };
                let rows = stmt.query_map([], |r| {
                    let acct = resolve_account(r, 9);
                    Ok((
                        cint(r, 0),
                        cstr(r, 1),
                        cstr(r, 2),
                        cfloat(r, 3),
                        cfloat(r, 4),
                        cint(r, 5),
                        cint(r, 6),
                        cstr(r, 7),
                        acct,
                        cint(r, 8),
                    ))
                });
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(e) => {
                        out.push(query_unusable_artifact(
                            case,
                            parent,
                            &file_name,
                            "ZICCLOUDSYNCINGOBJECT note",
                            &e,
                        ));
                        return out;
                    }
                };
                let mut drops = RowDrops::default();
                let mut notes = 0usize;
                let mut deleted_notes = 0usize;
                // Notes whose deletion could not be established: not marked,
                // and in a folder the failed folder lookup never reached.
                let mut deleted_unresolved = 0usize;
                let mut bodies_decoded = 0usize;
                let mut bodies_undecoded = 0usize;
                let mut bodies_absent = 0usize;
                let mut bodies_unread = 0usize;
                let mut capped = false;
                // What each note's attachments need to know of it.
                let mut note_info: HashMap<i64, notes_attachments::NoteInfo> = HashMap::new();
                for row in rows {
                    let (
                        pk,
                        title,
                        snippet,
                        created,
                        modified,
                        folder,
                        marked,
                        ident,
                        acct,
                        locked,
                    ) = match row {
                        Ok(r) => r,
                        Err(e) => {
                            drops.record(&e);
                            continue;
                        }
                    };
                    if notes >= MAX_NOTES {
                        capped = true;
                        break;
                    }
                    notes += 1;
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), json!("Note"));
                    m.insert("subtype".into(), json!("note"));
                    m.insert("platform".into(), json!("iOS"));
                    if let Some(pk) = pk {
                        m.insert("note_id".into(), json!(pk));
                    }
                    if let Some(t) = &title {
                        m.insert("title".into(), json!(t));
                    }
                    if let Some(s) = snippet {
                        m.insert("snippet".into(), json!(s));
                    }
                    if let Some(c) = created {
                        insert_cocoa(&mut m, "created", c, "ZICCLOUDSYNCINGOBJECT.ZCREATIONDATE");
                        insert_cocoa(&mut m, "date", c, "ZICCLOUDSYNCINGOBJECT.ZCREATIONDATE");
                    }
                    if let Some(md) = modified {
                        insert_cocoa(
                            &mut m,
                            "modified",
                            md,
                            "ZICCLOUDSYNCINGOBJECT.ZMODIFICATIONDATE",
                        );
                    }
                    if let Some(i) = ident {
                        m.insert("identifier".into(), json!(i));
                    }
                    if let Some(a) = acct {
                        m.insert("account_id".into(), json!(a));
                        if let Some(name) = accounts.get(&a) {
                            m.insert("account".into(), json!(name));
                        }
                    } else if accounts_failed && !account_cols.is_empty() {
                        // The account lookup failed: no account resolved is
                        // "could not look", not "none" (HUNT-232).
                        m.insert("account_unresolved".into(), json!(true));
                    }
                    let mut in_trash = Some(false);
                    if let Some(f) = folder {
                        m.insert("folder_id".into(), json!(f));
                        if let Some(fr) = folders.get(&f) {
                            if let Some(t) = &fr.title {
                                m.insert("folder".into(), json!(t));
                            }
                            in_trash = Some(fr.folder_type == Some(1));
                        } else if folders_failed {
                            // The note names a folder the failed lookup never
                            // reached, so whether it sits in Recently Deleted
                            // is not known — and is not "no" (HUNT-232).
                            m.insert("folder_unresolved".into(), json!(true));
                            in_trash = None;
                        }
                    }
                    let is_deleted = match (marked == Some(1), in_trash) {
                        (true, _) => Some(true),
                        (false, Some(t)) => Some(t),
                        (false, None) => None,
                    };
                    match is_deleted {
                        Some(true) => deleted_notes += 1,
                        Some(false) => {}
                        None => deleted_unresolved += 1,
                    }
                    m.insert("deleted".into(), json!(is_deleted));
                    if let Some(pk) = pk {
                        note_info.insert(
                            pk,
                            notes_attachments::NoteInfo {
                                title: title.clone(),
                                deleted: is_deleted,
                                account: acct,
                            },
                        );
                    }
                    if let Some(mk) = marked {
                        m.insert("marked_for_deletion".into(), json!(mk != 0));
                    }
                    m.insert("in_recently_deleted".into(), json!(in_trash));
                    let is_locked = locked.unwrap_or(0) != 0;
                    m.insert("password_protected".into(), json!(is_locked));
                    match pk.and_then(|pk| bodies.get(&pk)) {
                        Some((zdata, encrypted)) => {
                            m.insert("body_present".into(), json!(true));
                            if *encrypted || is_locked {
                                bodies_undecoded += 1;
                                m.insert("body_decoded".into(), json!(false));
                                m.insert("content_incomplete".into(), json!(true));
                                m.insert(
                                    "content_incomplete_reason".into(),
                                    json!(IncompleteReason::Encrypted.as_str()),
                                );
                                m.insert(
                                    "content_incomplete_detail".into(),
                                    json!("the note is password-protected: ZICNOTEDATA carries a crypto tag and the body is ciphertext"),
                                );
                            } else {
                                match notes_proto::note_text(zdata) {
                                    Ok(text) => {
                                        bodies_decoded += 1;
                                        m.insert("body".into(), json!(text));
                                        m.insert("body_decoded".into(), json!(true));
                                        m.insert("body_source".into(), json!("notestore_protobuf"));
                                    }
                                    Err(e) => {
                                        // The body is in the evidence and unread,
                                        // which is not a note with no body.
                                        bodies_undecoded += 1;
                                        m.insert("body_decoded".into(), json!(false));
                                        m.insert("body_undecoded_reason".into(), json!(e.as_str()));
                                        m.insert("body_bytes".into(), json!(zdata.len()));
                                        m.insert("content_incomplete".into(), json!(true));
                                        m.insert(
                                            "content_incomplete_reason".into(),
                                            json!(match e {
                                                notes_proto::NoteBodyError::InflateCapReached =>
                                                    IncompleteReason::CapReached.as_str(),
                                                _ => IncompleteReason::UnresolvedStructure.as_str(),
                                            }),
                                        );
                                    }
                                }
                            }
                        }
                        None if body_query_error.is_some() => {
                            bodies_unread += 1;
                            m.insert("body_unread".into(), json!(true));
                            m.insert(
                                "body_unread_reason".into(),
                                json!("ZICNOTEDATA query did not run"),
                            );
                        }
                        None => {
                            bodies_absent += 1;
                            m.insert("body_present".into(), json!(false));
                            if !has_note_data {
                                m.insert("body_table_absent".into(), json!(true));
                            }
                        }
                    }
                    m.insert("name".into(), json!(title.unwrap_or_else(|| "Note".into())));
                    out.push(parent_record(case, parent, Value::Object(m)));
                }
                if let Some(marker) = drops.marker(
                    case,
                    parent,
                    "NoteIncomplete",
                    "ZICCLOUDSYNCINGOBJECT",
                    notes,
                ) {
                    out.push(marker);
                }

                let mut s = serde_json::Map::new();
                s.insert("type".into(), json!("NotesSummary"));
                s.insert("platform".into(), json!("iOS"));
                s.insert("notes".into(), json!(notes));
                // Stated even when zero: "none were deleted" is a finding.
                s.insert("deleted_notes".into(), json!(deleted_notes));
                if deleted_unresolved > 0 {
                    s.insert("deleted_notes_unresolved".into(), json!(deleted_unresolved));
                }
                s.insert("folders".into(), json!(folders.len()));
                s.insert("bodies_decoded".into(), json!(bodies_decoded));
                s.insert("bodies_undecoded".into(), json!(bodies_undecoded));
                s.insert("bodies_absent".into(), json!(bodies_absent));
                s.insert("bodies_unread".into(), json!(bodies_unread));
                if let Some(e) = &body_query_error {
                    s.insert("body_query_did_not_run".into(), json!(true));
                    s.insert("body_query_error".into(), json!(e));
                }
                s.insert("entity_resolution".into(), json!(entity_resolution));
                if let Some(e) = note_ent {
                    s.insert("note_entity".into(), json!(e));
                }
                match (attachment_ent, has("Z_ENT")) {
                    (Some(ae), true) => {
                        // A count that would not run is not zero attachments.
                        match conn.query_row(
                            &format!(
                                "SELECT count(*) FROM ZICCLOUDSYNCINGOBJECT WHERE Z_ENT = {ae}"
                            ),
                            [],
                            |r| r.get::<_, i64>(0),
                        ) {
                            Ok(n) => {
                                s.insert("attachment_rows".into(), json!(n));
                            }
                            Err(e) => {
                                lookup_failures.push(format!("attachment count: {e}"));
                            }
                        }
                        // Each attachment, its media row and its file (§1.5).
                        let read = notes_attachments::read_attachments(
                            conn,
                            ds,
                            case,
                            parent,
                            &notes_attachments::Context {
                                attachment_ent: ae,
                                cols: &cols,
                                accounts: &accounts,
                                account_cols: &account_cols,
                                notes: &note_info,
                            },
                        );
                        s.insert("attachments_decoded".into(), json!(true));
                        s.insert("attachments".into(), json!(read.records.len()));
                        s.insert("deleted_attachments".into(), json!(read.deleted));
                        s.insert("attachment_media_present".into(), json!(read.media_present));
                        s.insert("attachment_media_absent".into(), json!(read.media_absent));
                        s.insert(
                            "attachment_media_unresolved".into(),
                            json!(read.media_unresolved),
                        );
                        if read.capped {
                            s.insert("attachments_capped".into(), json!(true));
                        }
                        if let Some(e) = &read.error {
                            lookup_failures.push(format!("attachments: {e}"));
                        }
                        for a in out.iter_mut() {
                            if a.metadata["type"] != "Note" {
                                continue;
                            }
                            if let Some(id) = a.metadata["note_id"].as_i64() {
                                let n = read.per_note.get(&id).copied().unwrap_or(0);
                                a.metadata["attachments"] = json!(n);
                            }
                        }
                        out.extend(read.records);
                    }
                    _ => {
                        s.insert("attachment_entity_unresolved".into(), json!(true));
                    }
                }
                if let Some(te) = entities.get("ICLegacyTombstone") {
                    match conn.query_row(
                        &format!("SELECT count(*) FROM ZICCLOUDSYNCINGOBJECT WHERE Z_ENT = {te}"),
                        [],
                        |r| r.get::<_, i64>(0),
                    ) {
                        Ok(n) => {
                            s.insert("tombstone_rows".into(), json!(n));
                        }
                        Err(e) => {
                            lookup_failures.push(format!("tombstone count: {e}"));
                        }
                    }
                }
                if !lookup_failures.is_empty() {
                    let detail = format!(
                        "{} lookup(s) the notes' folder, account and deletion state and this \
                         summary's counts are built on did not complete; a note marked \
                         folder_unresolved or account_unresolved is one they did not reach, and \
                         its deletion state is not known unless it is marked for deletion: {}",
                        lookup_failures.len(),
                        lookup_failures.join("; ")
                    );
                    s.insert("lookup_failures".into(), json!(lookup_failures));
                    s.insert("content_incomplete".into(), json!(true));
                    s.insert(
                        "content_incomplete_reason".into(),
                        json!(IncompleteReason::UnresolvedStructure.as_str()),
                    );
                    s.insert("content_incomplete_detail".into(), json!(detail));
                }
                s.insert("rows_dropped".into(), json!(drops.dropped()));
                s.insert("records_recovered".into(), json!(notes));
                if capped || drops.dropped() > 0 {
                    s.insert("inventory_incomplete".into(), json!(true));
                    s.insert(
                        "inventory_incomplete_reason".into(),
                        json!(if capped {
                            IncompleteReason::CapReached.as_str()
                        } else {
                            IncompleteReason::UnresolvedStructure.as_str()
                        }),
                    );
                    if capped {
                        s.insert("cap".into(), json!(MAX_NOTES));
                    }
                }
                s.insert(
                    "name".into(),
                    json!(format!(
                        "Notes: {notes} note(s), {deleted_notes} deleted, {} folder(s), {bodies_decoded} bod(y/ies) read",
                        folders.len()
                    )),
                );
                out.push(parent_record(case, parent, Value::Object(s)));
                out
            },
        ))
    }
}

// --- Photos catalog (Photos.sqlite) -----------------------------------------

pub struct PhotosParser;

/// The album↔asset join table, found rather than named.
///
/// Core Data names it `Z_<albumEnt>ASSETS` with columns `Z_<albumEnt>ALBUMS`
/// and `Z_<assetEnt>ASSETS`, and the entity numbers move between iOS
/// releases (`Z_27ASSETS` on iOS 15, `Z_26ASSETS`/`Z_28ASSETS`/`Z_30ASSETS`
/// on others). A hardcoded name yields silent zero membership on every
/// other release, which is the one wrong answer this exists to prevent.
struct AlbumJoin {
    table: String,
    album_col: String,
    asset_col: String,
    album_ent: i64,
}

/// `Ok(None)` is a store with no join table this reader recognises (a shape);
/// `Err` is one whose join table could not be looked for or whose column list
/// would not read, which used to be the same `None` (HUNT-214).
fn discover_album_join(
    conn: &Connection,
    entities: &HashMap<String, i64>,
) -> Result<Option<AlbumJoin>, String> {
    let Some(album_ent) = ["Album", "GenericAlbum"]
        .iter()
        .find_map(|n| entities.get(*n).copied())
    else {
        return Ok(None);
    };
    let Some(asset_ent) = ["Asset", "GenericAsset"]
        .iter()
        .find_map(|n| entities.get(*n).copied())
    else {
        return Ok(None);
    };
    let table = format!("Z_{album_ent}ASSETS");
    match probe_table(conn, &table) {
        Presence::Present => {}
        Presence::Absent => return Ok(None),
        Presence::Undetermined(why) => return Err(why),
    }
    let cols = probe_columns(conn, &table)?;
    let album_col = format!("Z_{album_ent}ALBUMS");
    let asset_col = format!("Z_{asset_ent}ASSETS");
    if !cols.contains(&album_col.to_ascii_lowercase())
        || !cols.contains(&asset_col.to_ascii_lowercase())
    {
        return Ok(None);
    }
    Ok(Some(AlbumJoin {
        table,
        album_col,
        asset_col,
        album_ent,
    }))
}

impl ForensicsModule for PhotosParser {
    fn id(&self) -> &str {
        "plugin.ios.photos"
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
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        Ok(with_db(
            artifact,
            &["photos.sqlite"],
            "photos",
            |conn, _ds, case, parent| {
                // iOS 12 uses ZGENERICASSET; newer iOS uses ZASSET.
                let asset = match expected_table(
                    conn,
                    case,
                    parent,
                    "Photos.sqlite",
                    &["ZGENERICASSET", "ZASSET"],
                    true,
                    true,
                ) {
                    Ok(asset) => asset,
                    Err(owed) => return owed,
                };
                // Every lookup the album counts are built on. Each failure is
                // named on the summary; none of them is ever a zero (HUNT-214).
                let mut lookup_failures: Vec<String> = Vec::new();
                let entities = core_data_entities(conn).unwrap_or_else(|why| {
                    lookup_failures.push(format!("Core Data entity names: {why}"));
                    HashMap::new()
                });
                let supers = core_data_supers(conn).unwrap_or_else(|why| {
                    lookup_failures.push(format!("Core Data entity parents: {why}"));
                    HashMap::new()
                });
                let join = discover_album_join(conn, &entities).unwrap_or_else(|why| {
                    lookup_failures.push(format!("album-asset join table: {why}"));
                    None
                });

                // Membership: album -> count, asset -> album ids. Read to the
                // end or not at all: a membership walk that stopped part-way
                // would publish short counts as exact ones.
                let mut album_counts: HashMap<i64, i64> = HashMap::new();
                let mut asset_albums: HashMap<i64, Vec<i64>> = HashMap::new();
                let mut memberships = 0usize;
                let mut membership_error: Option<String> = None;
                if let Some(j) = &join {
                    let sql = format!(
                        "SELECT \"{}\", \"{}\" FROM \"{}\"",
                        j.album_col, j.asset_col, j.table
                    );
                    let read: rusqlite::Result<Vec<(Option<i64>, Option<i64>)>> =
                        conn.prepare(&sql).and_then(|mut stmt| {
                            stmt.query_map([], |r| Ok((cint(r, 0), cint(r, 1))))?
                                .collect()
                        });
                    match read {
                        Ok(rows) => {
                            for row in rows {
                                if let (Some(al), Some(a)) = row {
                                    memberships += 1;
                                    *album_counts.entry(al).or_default() += 1;
                                    asset_albums.entry(a).or_default().push(al);
                                }
                            }
                        }
                        Err(e) => {
                            let why = format!("`{}` would not read: {e}", j.table);
                            lookup_failures.push(format!("album memberships: {why}"));
                            membership_error = Some(why);
                        }
                    }
                }

                let sql = format!(
                    "SELECT a.ZFILENAME, a.ZDATECREATED, a.ZLATITUDE, a.ZLONGITUDE, \
                            a.ZWIDTH, a.ZHEIGHT, a.ZKIND, a.ZFAVORITE, a.ZTRASHEDSTATE, \
                            aa.ZORIGINALFILENAME, a.Z_PK \
                     FROM {asset} a \
                     LEFT JOIN ZADDITIONALASSETATTRIBUTES aa ON aa.ZASSET = a.Z_PK \
                     ORDER BY a.ZDATECREATED"
                );
                let mut stmt = match conn.prepare(&sql) {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        return vec![query_unusable_artifact(
                            case,
                            parent,
                            "Photos.sqlite",
                            asset,
                            &e,
                        )];
                    }
                };
                let rows = stmt.query_map([], |r| {
                    Ok((
                        cstr(r, 0),
                        cfloat(r, 1),
                        cfloat(r, 2),
                        cfloat(r, 3),
                        cint(r, 4),
                        cint(r, 5),
                        cint(r, 6),
                        cint(r, 7),
                        cint(r, 8),
                        cstr(r, 9),
                        cint(r, 10),
                    ))
                });
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(e) => {
                        return vec![query_unusable_artifact(
                            case,
                            parent,
                            "Photos.sqlite",
                            asset,
                            &e,
                        )];
                    }
                };
                let mut out = Vec::new();
                let mut drops = RowDrops::default();
                let mut assets = 0usize;
                for row in rows {
                    let (fname, created, lat, lon, w, h, kind, fav, trashed, orig, pk) = match row {
                        Ok(r) => r,
                        Err(e) => {
                            drops.record(&e);
                            continue;
                        }
                    };
                    assets += 1;
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), json!("PhotoAsset"));
                    m.insert("subtype".into(), json!("photo_asset"));
                    m.insert("platform".into(), json!("iOS"));
                    if let Some(pk) = pk {
                        m.insert("asset_id".into(), json!(pk));
                        if let Some(ids) = asset_albums.get(&pk) {
                            m.insert("album_ids".into(), json!(ids));
                        }
                    }
                    let display = orig.clone().or_else(|| fname.clone());
                    if let Some(f) = fname {
                        m.insert("filename".into(), json!(f));
                    }
                    if let Some(o) = orig {
                        m.insert("original_filename".into(), json!(o));
                    }
                    if let Some(c) = created {
                        insert_cocoa(&mut m, "date", c, &format!("{asset}.ZDATECREATED"));
                    }
                    // iOS stores -180 for "no location".
                    if let (Some(la), Some(lo)) = (lat, lon) {
                        if la.abs() <= 90.0 && lo.abs() <= 180.0 && !(la == -180.0 || lo == -180.0)
                        {
                            m.insert("latitude".into(), json!(la));
                            m.insert("longitude".into(), json!(lo));
                            m.insert("has_gps".into(), json!(true));
                        }
                    }
                    if let Some(w) = w {
                        m.insert("width".into(), json!(w));
                    }
                    if let Some(h) = h {
                        m.insert("height".into(), json!(h));
                    }
                    m.insert("media_kind".into(), json!(photos_media_kind(kind)));
                    // NULL is the column recording nothing: `null`, not `false`.
                    m.insert("favorite".into(), flag_or_null(fav, |v| v != 0));
                    m.insert("deleted".into(), flag_or_null(trashed, |v| v != 0));
                    m.insert(
                        "name".into(),
                        json!(display.unwrap_or_else(|| "asset".into())),
                    );
                    out.push(parent_record(case, parent, Value::Object(m)));
                }
                if let Some(marker) =
                    drops.marker(case, parent, "PhotoAssetIncomplete", asset, assets)
                {
                    out.push(marker);
                }

                // Albums. The join table belongs to the `Album` entity and
                // to everything that descends from it (CloudSharedAlbum,
                // PhotoStreamAlbum, ...). `FetchingAlbum` and `Folder` descend
                // from `GenericAlbum` instead and have no membership table,
                // so theirs is stated as unresolved, never as 0.
                let mut albums = 0usize;
                let mut entity_histogram: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                let album_table = match probe_table(conn, "ZGENERICALBUM") {
                    Presence::Present => match probe_columns(conn, "ZGENERICALBUM") {
                        Ok(cols) => Some(cols),
                        Err(why) => {
                            lookup_failures.push(format!("albums: {why}"));
                            None
                        }
                    },
                    Presence::Absent => None,
                    Presence::Undetermined(why) => {
                        lookup_failures.push(format!("albums: {why}"));
                        None
                    }
                };
                let album_table_present = album_table.is_some();
                if let Some(acols) = album_table {
                    let ent_names: HashMap<i64, &str> =
                        entities.iter().map(|(n, e)| (*e, n.as_str())).collect();
                    let opt = |c: &str| {
                        if acols.contains(&c.to_ascii_lowercase()) {
                            c.to_string()
                        } else {
                            "NULL".to_string()
                        }
                    };
                    let sql = format!(
                        "SELECT Z_PK, {}, ZKIND, ZTITLE, {}, {}, {}, {}, {}, {} FROM ZGENERICALBUM ORDER BY Z_PK",
                        opt("Z_ENT"),
                        opt("ZCACHEDCOUNT"),
                        opt("ZTRASHEDSTATE"),
                        opt("ZCREATIONDATE"),
                        opt("ZUUID"),
                        opt("ZPARENTFOLDER"),
                        opt("ZCLOUDOWNEREMAILKEY"),
                    );
                    let album_query_failed = |e: rusqlite::Error| {
                        format!("albums: the `ZGENERICALBUM` query did not run: {e}")
                    };
                    match conn.prepare(&sql) {
                        Err(e) => lookup_failures.push(album_query_failed(e)),
                        Ok(mut stmt) => {
                            let rows = stmt.query_map([], |r| {
                                Ok((
                                    cint(r, 0),
                                    cint(r, 1),
                                    cint(r, 2),
                                    cstr(r, 3),
                                    cint(r, 4),
                                    cint(r, 5),
                                    cfloat(r, 6),
                                    cstr(r, 7),
                                    cint(r, 8),
                                    cstr(r, 9),
                                ))
                            });
                            match rows {
                                Err(e) => lookup_failures.push(album_query_failed(e)),
                                Ok(rows) => {
                                    let mut adrops = RowDrops::default();
                                    for row in rows {
                                        let (
                                            pk,
                                            ent,
                                            kind,
                                            title,
                                            cached,
                                            trashed,
                                            created,
                                            uuid,
                                            folder,
                                            owner,
                                        ) = match row {
                                            Ok(r) => r,
                                            Err(e) => {
                                                adrops.record(&e);
                                                continue;
                                            }
                                        };
                                        albums += 1;
                                        let ent_name = ent
                                            .and_then(|e| ent_names.get(&e).copied())
                                            .map(str::to_string)
                                            .unwrap_or_else(|| "unknown".into());
                                        *entity_histogram.entry(ent_name.clone()).or_default() += 1;
                                        let mut m = serde_json::Map::new();
                                        m.insert("type".into(), json!("PhotoAlbum"));
                                        m.insert("subtype".into(), json!("photo_album"));
                                        m.insert("platform".into(), json!("iOS"));
                                        if let Some(pk) = pk {
                                            m.insert("album_id".into(), json!(pk));
                                        }
                                        if let Some(e) = ent {
                                            m.insert("entity_id".into(), json!(e));
                                        }
                                        m.insert("entity".into(), json!(ent_name));
                                        if let Some(k) = kind {
                                            m.insert("kind".into(), json!(k));
                                        }
                                        if let Some(t) = &title {
                                            m.insert("title".into(), json!(t));
                                        }
                                        if let Some(c) = cached {
                                            m.insert("cached_count".into(), json!(c));
                                        }
                                        m.insert(
                                            "trashed".into(),
                                            json!(trashed.map(|v| v != 0).unwrap_or(false)),
                                        );
                                        if let Some(c) = created {
                                            insert_cocoa(
                                                &mut m,
                                                "created",
                                                c,
                                                "ZGENERICALBUM.ZCREATIONDATE",
                                            );
                                            insert_cocoa(
                                                &mut m,
                                                "date",
                                                c,
                                                "ZGENERICALBUM.ZCREATIONDATE",
                                            );
                                        }
                                        if let Some(u) = uuid {
                                            m.insert("uuid".into(), json!(u));
                                        }
                                        if let Some(f) = folder {
                                            m.insert("parent_folder_id".into(), json!(f));
                                        }
                                        if let Some(o) = owner {
                                            m.insert("cloud_owner_email".into(), json!(o));
                                        }
                                        match (&join, pk, ent) {
                                            (Some(_), _, _) if membership_error.is_some() => {
                                                m.insert(
                                                    "asset_count_unresolved".into(),
                                                    json!(true),
                                                );
                                                m.insert(
                                                    "asset_count_unresolved_reason".into(),
                                                    json!(format!(
                                                "the album-membership query did not complete: {}",
                                                membership_error.as_deref().unwrap_or_default()
                                            )),
                                                );
                                            }
                                            (Some(j), Some(pk), Some(e))
                                                if descends_from(&supers, e, j.album_ent) =>
                                            {
                                                m.insert(
                                                    "asset_count".into(),
                                                    json!(album_counts
                                                        .get(&pk)
                                                        .copied()
                                                        .unwrap_or(0)),
                                                );
                                            }
                                            _ => {
                                                m.insert(
                                                    "asset_count_unresolved".into(),
                                                    json!(true),
                                                );
                                                let reason = match &join {
                                                    None if !lookup_failures.is_empty() => format!(
                                                "the lookups that find the album-asset join \
                                                 table did not complete: {}",
                                                lookup_failures.join("; ")
                                            ),
                                                    None => "no album-asset join table was found"
                                                        .to_string(),
                                                    Some(j) => {
                                                        let root = ent_names
                                                            .get(&j.album_ent)
                                                            .copied()
                                                            .unwrap_or("the root album entity");
                                                        format!(
                                                    "entity {ent_name} does not descend from {root} (Z_ENT {}), whose {} is the only album-asset join table found",
                                                    j.album_ent, j.table
                                                )
                                                    }
                                                };
                                                m.insert(
                                                    "asset_count_unresolved_reason".into(),
                                                    json!(reason),
                                                );
                                            }
                                        }
                                        m.insert(
                                            "name".into(),
                                            json!(format!(
                                                "Photo album: {}",
                                                title.as_deref().unwrap_or("(untitled)")
                                            )),
                                        );
                                        out.push(parent_record(case, parent, Value::Object(m)));
                                    }
                                    if adrops.dropped() > 0 {
                                        lookup_failures.push(format!(
                                            "albums: {} `ZGENERICALBUM` row(s) would not read ({})",
                                            adrops.dropped(),
                                            adrops.first_error().unwrap_or_default()
                                        ));
                                    }
                                    if let Some(marker) = adrops.marker(
                                        case,
                                        parent,
                                        "PhotoAlbumIncomplete",
                                        "ZGENERICALBUM",
                                        albums,
                                    ) {
                                        out.push(marker);
                                    }
                                }
                            }
                        }
                    }
                }

                let mut s = serde_json::Map::new();
                s.insert("type".into(), json!("PhotosSummary"));
                s.insert("platform".into(), json!("iOS"));
                s.insert("asset_table".into(), json!(asset));
                s.insert("assets".into(), json!(assets));
                s.insert("albums".into(), json!(albums));
                s.insert("album_table_present".into(), json!(album_table_present));
                s.insert("album_entity_histogram".into(), json!(entity_histogram));
                match &join {
                    Some(j) => {
                        s.insert("album_membership_present".into(), json!(true));
                        s.insert("album_membership_table".into(), json!(j.table));
                        s.insert("album_memberships".into(), json!(memberships));
                    }
                    None => {
                        s.insert("album_membership_present".into(), json!(false));
                        s.insert(
                            "album_membership_unresolved_reason".into(),
                            json!(IncompleteReason::UnresolvedStructure.as_str()),
                        );
                    }
                }
                // Faces and people are counted and not decoded: no device
                // held has a row in either.
                // A count that would not read is a failure, not an absent
                // table: `table_count` said "absent" for both.
                for (table, field) in [("ZDETECTEDFACE", "face_rows"), ("ZPERSON", "person_rows")] {
                    match table_count_checked(conn, table) {
                        Ok(Some(n)) => {
                            s.insert(field.into(), json!(n));
                        }
                        Ok(None) => {
                            s.insert(format!("{field}_table_absent"), json!(true));
                        }
                        Err(why) => {
                            lookup_failures.push(format!("{field}: {why}"));
                        }
                    }
                }
                if !lookup_failures.is_empty() {
                    let detail = format!(
                        "{} lookup(s) this summary's album and face counts are built on did not \
                         complete, so those counts are not the library's: {}",
                        lookup_failures.len(),
                        lookup_failures.join("; ")
                    );
                    s.insert("lookup_failures".into(), json!(lookup_failures));
                    s.insert("content_incomplete".into(), json!(true));
                    s.insert(
                        "content_incomplete_reason".into(),
                        json!(IncompleteReason::UnresolvedStructure.as_str()),
                    );
                    s.insert("content_incomplete_detail".into(), json!(detail));
                }
                s.insert("faces_decoded".into(), json!(false));
                s.insert("records_recovered".into(), json!(assets + albums));
                s.insert(
                    "name".into(),
                    json!(format!(
                        "Photos library: {assets} asset(s), {albums} album(s), {memberships} album membership(s)"
                    )),
                );
                out.push(parent_record(case, parent, Value::Object(s)));
                out
            },
        ))
    }
}

// --- PowerLog (CurrentPowerlog.PLSQL) ---------------------------------------

pub struct PowerLogParser;

impl ForensicsModule for PowerLogParser {
    fn id(&self) -> &str {
        "plugin.ios.powerlog"
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
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Accept CurrentPowerlog.PLSQL and its rotated `*.PLSQL` siblings.
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let base = basename(name);
        if !(base.ends_with(".plsql") || base.starts_with("currentpowerlog")) {
            return Ok(Vec::new());
        }
        Ok(with_db(
            artifact,
            &[base.as_str()],
            "plog",
            |conn, _ds, case, parent| {
                let mut out = Vec::new();
                // 1) Torch (flashlight) on/off events — a high-value activity signal.
                let torch = powerlog_torch(conn);
                let torch_dropped = torch.dropped;
                for (ts, state) in torch.rows {
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), json!("PowerLogEvent"));
                    m.insert("subtype".into(), json!("powerlog_event"));
                    m.insert("platform".into(), json!("iOS"));
                    m.insert("category".into(), json!("torch"));
                    // On/off only when the state is actually recorded; an
                    // absent/NULL state is surfaced honestly as unknown.
                    let (event, name) = match state {
                        Some(s) if s != 0 => ("flashlight on", "Flashlight ON"),
                        Some(_) => ("flashlight off", "Flashlight OFF"),
                        None => ("flashlight (state unknown)", "Flashlight event"),
                    };
                    m.insert("event".into(), json!(event));
                    if let Some(s) = state {
                        m.insert("state".into(), json!(s));
                    }
                    if let Some((secs, nanos)) = ts {
                        insert_instant(&mut m, "date", secs, nanos);
                    }
                    m.insert("name".into(), json!(name));
                    out.push(parent_record(case, parent, Value::Object(m)));
                }
                // 2) An inventory of the PL* tables present, so the examiner can see
                //    which activity signals (camera, app usage, battery, ...) this
                //    PowerLog can corroborate — without over-parsing an unvalidated
                //    schema.
                // The summary is owed whenever there is something to say: a
                // PL* inventory, an inventory query that did not run, or a torch
                // table that was there and not read. A torch read that failed
                // used to leave `torch_rows_dropped 0` on a summary that said
                // nothing had gone wrong (HUNT-190).
                let inventory = powerlog_table_inventory(conn);
                let torch_failed = !matches!(torch.status, "read" | "table_absent");
                let owed = torch_failed
                    || match &inventory {
                        Ok((tables, dropped)) => !tables.is_empty() || *dropped > 0,
                        Err(_) => true,
                    };
                if owed {
                    let (tables, tables_dropped, inventory_error) = match inventory {
                        Ok((tables, dropped)) => (tables, dropped, None),
                        Err(e) => (Vec::new(), 0, Some(e)),
                    };
                    let mut m = serde_json::Map::new();
                    m.insert("type".into(), json!("PowerLogSummary"));
                    m.insert("subtype".into(), json!("powerlog_summary"));
                    m.insert("platform".into(), json!("iOS"));
                    m.insert("table_count".into(), json!(tables.len()));
                    m.insert("tables".into(), json!(tables));
                    m.insert("torch_rows_dropped".into(), json!(torch_dropped));
                    m.insert("table_names_dropped".into(), json!(tables_dropped));
                    // `read` | `table_absent` | `undetermined` |
                    // `query_did_not_run` | `time_column_unresolved`.
                    m.insert("torch_status".into(), json!(torch.status));
                    if let Some(e) = &torch.error {
                        m.insert("torch_query_error".into(), json!(e));
                    }
                    if let Some(e) = &inventory_error {
                        m.insert("table_inventory_did_not_run".into(), json!(true));
                        m.insert("table_inventory_error".into(), json!(e));
                    }
                    // Rows and table names that would not decode, a torch
                    // table that was not read, and an inventory that did not
                    // run are recorded here rather than thrown away: the
                    // counts above are a lower bound whenever any is so
                    // (B4-012, HUNT-190).
                    if torch_dropped > 0
                        || tables_dropped > 0
                        || torch_failed
                        || inventory_error.is_some()
                    {
                        m.insert("content_incomplete".into(), json!(true));
                        m.insert(
                            "content_incomplete_reason".into(),
                            json!(IncompleteReason::UnresolvedStructure.as_str()),
                        );
                        m.insert("inventory_incomplete".into(), json!(true));
                        m.insert(
                            "inventory_incomplete_reason".into(),
                            json!(IncompleteReason::UnresolvedStructure.as_str()),
                        );
                        let mut why = Vec::new();
                        if torch_failed {
                            why.push(format!(
                                "the torch table was not read ({}{})",
                                torch.status,
                                torch
                                    .error
                                    .as_deref()
                                    .map(|e| format!(": {e}"))
                                    .unwrap_or_default()
                            ));
                        }
                        if torch_dropped > 0 {
                            why.push(format!("{torch_dropped} torch row(s) would not decode"));
                        }
                        if let Some(e) = &inventory_error {
                            why.push(format!("the PL* table inventory did not run: {e}"));
                        }
                        if tables_dropped > 0 {
                            why.push(format!("{tables_dropped} table name(s) would not decode"));
                        }
                        m.insert("content_incomplete_detail".into(), json!(why.join("; ")));
                    }
                    m.insert(
                        "name".into(),
                        json!(format!("PowerLog ({} tables)", tables.len())),
                    );
                    out.push(parent_record(case, parent, Value::Object(m)));
                }
                out
            },
        ))
    }
}

/// What reading `PLCameraAgent_EventForward_Torch` produced, and whether it
/// was read at all.
///
/// `status` is `read`, `table_absent` (the catalogue answered: this PowerLog
/// has no torch table — a finding), or one of the answers that mean the torch
/// events were NOT looked at: `undetermined` (the catalogue would not say),
/// `query_did_not_run` (the column list, the prepare or the query failed;
/// `error` carries SQLite's text) and `time_column_unresolved` (no column this
/// reader recognises as the event time). Each of those used to be `None` —
/// no events and nothing saying why (HUNT-190).
/// One torch row: the event instant (Unix seconds and nanos) and the state.
type TorchRow = (Option<(i64, u32)>, Option<i64>);

struct TorchRead {
    rows: Vec<TorchRow>,
    dropped: usize,
    status: &'static str,
    error: Option<String>,
}

impl TorchRead {
    fn not_read(status: &'static str, error: Option<String>) -> Self {
        Self {
            rows: Vec::new(),
            dropped: 0,
            status,
            error,
        }
    }
}

/// Rows from `PLCameraAgent_EventForward_Torch` as `(unix_seconds, state)`,
/// resolving the timestamp/state columns at runtime.
///
/// Carries how many rows would not decode. The count is not optional: a torch
/// event is an activity signal placing somebody with the phone at a time, and
/// one silently dropped leaves a gap in a timeline that reads as an absence of
/// activity (B4-012).
fn powerlog_torch(conn: &Connection) -> TorchRead {
    let table = "PLCameraAgent_EventForward_Torch";
    match probe_table(conn, table) {
        Presence::Present => {}
        Presence::Absent => return TorchRead::not_read("table_absent", None),
        Presence::Undetermined(why) => return TorchRead::not_read("undetermined", Some(why)),
    }
    // `probe_columns` lower-cases every name and returns a set, so sort for a
    // deterministic pick when more than one column matches a predicate.
    // SQLite resolves identifiers case-insensitively, so the lower-cased name
    // still names the original column in the SQL below.
    let cols = match probe_columns(conn, table) {
        Ok(cols) => cols,
        Err(why) => return TorchRead::not_read("query_did_not_run", Some(why)),
    };
    let mut names: Vec<&str> = cols.iter().map(String::as_str).collect();
    names.sort_unstable();
    let Some(ts_col) = names
        .iter()
        .find(|c| c.contains("timestamp") || **c == "time" || c.contains("date"))
    else {
        return TorchRead::not_read(
            "time_column_unresolved",
            Some(format!(
                "no column of `{table}` is recognised as the event time (columns: {})",
                names.join(", ")
            )),
        );
    };
    // The state column is discovered, never fabricated: without it the on/off
    // state is genuinely unknown and must NOT be defaulted to "on".
    let state_col = names.iter().find(|c| {
        c.contains("state") || c.contains("value") || c.contains("level") || **c == "torch"
    });
    let sql = match state_col {
        Some(sc) => format!("SELECT \"{ts_col}\", \"{sc}\" FROM \"{table}\" ORDER BY \"{ts_col}\""),
        None => format!("SELECT \"{ts_col}\", NULL FROM \"{table}\" ORDER BY \"{ts_col}\""),
    };
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(e) => return TorchRead::not_read("query_did_not_run", Some(e.to_string())),
    };
    let rows = match stmt.query_map([], |r| Ok((cfloat(r, 0), cint(r, 1)))) {
        Ok(rows) => rows,
        Err(e) => return TorchRead::not_read("query_did_not_run", Some(e.to_string())),
    };
    let mut out = Vec::new();
    let mut dropped = 0usize;
    for row in rows {
        match row {
            Ok((ts, state)) => out.push((ts.and_then(powerlog_time), state)),
            // A dropped torch row is an activity event that happened and is
            // not in the timeline; it is counted rather than lost.
            Err(_) => dropped += 1,
        }
    }
    TorchRead {
        rows: out,
        dropped,
        status: "read",
        error: None,
    }
}

/// PowerLog timestamps are usually Unix seconds; a small value is Core Data
/// (2001-epoch). Normalise to Unix seconds plus the sub-second nanoseconds.
///
/// The column is REAL in both bases and the fraction is evidence: a torch
/// switched on and off again inside a second is two events, and truncating the
/// float collapses them onto one instant with no order between them. Both
/// branches split through the shared converter so the same instant does not
/// decode differently depending on which base the row was written in.
fn powerlog_time(v: f64) -> Option<(i64, u32)> {
    // Anything before ~2001 in Unix terms is really a Core Data offset. The
    // 0/negative and non-finite sentinels are rejected inside both converters.
    if v < COCOA_EPOCH as f64 {
        cocoa_secs_to_unix_nanos(v)
    } else {
        unix_secs_f64_to_nanos(v)
    }
}

/// The `PL*` tables present, and how many names would not read.
///
/// The count travels because the inventory is what tells an examiner which
/// activity signals this PowerLog could corroborate; a short list presented as
/// whole understates what the device recorded.
///
/// `Err` carries SQLite's error when the inventory query did not run — a
/// third answer, never folded into "no PL* tables" (HUNT-190).
fn powerlog_table_inventory(conn: &Connection) -> Result<(Vec<String>, usize), String> {
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'PL%' ORDER BY name",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut tables = Vec::new();
    let mut dropped = 0usize;
    for row in rows {
        match row {
            Ok(name) => tables.push(name),
            Err(_) => dropped += 1,
        }
    }
    Ok((tables, dropped))
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_remainder;
