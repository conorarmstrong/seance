#![forbid(unsafe_code)]
//! WhatsApp Message Parser Module
//!
//! Parses WhatsApp databases extracting messages, contacts, and group info
//! as forensic artifacts.
//!
//! ## Supported Databases
//!
//! ### iOS (ChatStorage.sqlite)
//! - Core Data schema with ZWAMESSAGE, ZWACHATSESSION, ZWAPROFILEPUSHNAME tables
//! - Timestamps: Core Data epoch (seconds since 2001-01-01), stored as REAL.
//!   `date` carries the whole seconds and `date_ns` the full-precision instant
//!   whenever the column recorded a fraction — the fraction is what orders two
//!   messages inside one second, on the record and on the unified timeline.
//!
//! ### Android (msgstore.db)
//! - Standard SQLite schema with message, chat, jid tables
//! - Timestamps: Unix epoch milliseconds
//!
//! ## Schema support
//!
//! Every message column is read through a `FieldMap` (see `schema_support`),
//! and each parsed store emits one `WhatsAppIncomplete` record of
//! `warning_class: ParserStaleWarning` saying what this parser may claim about
//! its schema: no validated range (`ANDROID_SCHEMA_SUPPORT` / `IOS_SCHEMA_SUPPORT`
//! say why: a real Android store is held but its `PRAGMA user_version` is a constant
//! 1, and no iOS store is held), the
//! `PRAGMA user_version` an Android store carries (0 is reported as "not
//! recorded", never as version 0; the iOS Core Data store's model version is
//! not read at all), and any logical field no column resolved — which is the
//! only case that stamps `content_incomplete` (reason `unvalidated`).

#[cfg(test)]
mod tests;

#[cfg(test)]
mod schema_golden_tests;

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::time::{cocoa_secs_to_unix_nanos, unix_ns};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    cap_marker, probe_table, unreadable_store_marker, CapCounter, FieldMap, Presence, RowDrops,
    SchemaProbe,
};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

mod schema_support;
// crypt14 backup decryption (§5.7).
pub mod crypt14;
mod gcm;
// Encrypted backups and their key file in ingest (§5.7).
mod backup;
use schema_support::{
    field_expr, user_version, SchemaBound, SchemaCheck, SchemaSupport, SchemaVersion,
};

/// The reason both declarations below are Unranged.
///
/// Android: a real `msgstore.db` IS held since 2026-09-26 (the Hickman Android 14
/// Pixel 7a, WhatsApp 2.24.14.81; 230 messages read, columns resolved, no schema
/// marker — `the_real_android14_msgstore_resolves_every_field`). It is still not
/// ranged, because `PRAGMA user_version` reads 1 on every msgstore this project
/// holds (that store and the wa-crypt-tools vectors alike), so it cannot detect
/// drift; WhatsApp's own signal is `props.msgtore_db_schema_version`, which this
/// build does not read. iOS: no `ChatStorage.sqlite` is held (the iOS 2022 FFS
/// holds none).
const UNRANGED_WHY: &str =
    "the Android store's PRAGMA user_version is a constant 1 in every real msgstore held and \
     cannot detect drift, and no iOS ChatStorage.sqlite is held; the schema version is \
     recorded, not ranged";

/// What this parser may say about an Android `msgstore.db` schema version.
/// Once a real store is read, its `PRAGMA user_version` becomes the
/// single-point range `n..=n`, with the file named as evidence.
const ANDROID_SCHEMA_SUPPORT: SchemaSupport = SchemaSupport {
    app: "whatsapp-android",
    bound: SchemaBound::Unranged { why: UNRANGED_WHY },
};

/// What this parser may say about an iOS `ChatStorage.sqlite` schema version.
///
/// The store is Core Data, whose model version is the `NSStoreModelVersion…`
/// entries of `Z_METADATA.Z_PLIST` — not `PRAGMA user_version`, which reads 0
/// on every Core Data store this project has opened. Until this build reads
/// `Z_METADATA`, the version is reported as not read rather than as 0.
const IOS_SCHEMA_SUPPORT: SchemaSupport = SchemaSupport {
    app: "whatsapp-ios",
    bound: SchemaBound::Unranged { why: UNRANGED_WHY },
};

/// Where the iOS store keeps its version, and why this build does not read it.
const IOS_VERSION_NOT_READ: SchemaVersion = SchemaVersion::NotRead {
    locator: "coredata_model",
    why: "ChatStorage.sqlite is a Core Data store whose model version lives in \
          Z_METADATA.Z_PLIST, which this build does not read; PRAGMA user_version is not that \
          version and is not reported",
};

/// Logical fields of the modern Android `message` table and the physical
/// columns that have carried each across msgstore generations. A column
/// WhatsApp renames is a candidate added here, and until it is, the schema
/// record names the logical field that no longer resolves.
const ANDROID_MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("key_id", &["key_id"]),
    ("text", &["text_data", "data"]),
    ("sent_at", &["timestamp"]),
    ("from_me", &["from_me", "key_from_me"]),
    ("status", &["status"]),
    ("media_type", &["media_wa_type", "message_type"]),
    ("media_size", &["media_size"]),
    ("starred", &["starred"]),
];

/// Without text, a time and a direction a row is not an evidentiary message.
/// A renamed `from_me` used to make every message direction-unknown with
/// nothing on the record saying so.
const ANDROID_REQUIRED_FIELDS: &[&str] = &["text", "sent_at", "from_me"];

/// The legacy Android `messages` table.
const LEGACY_MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("id", &["_id"]),
    ("remote_jid", &["key_remote_jid"]),
    ("from_me", &["key_from_me"]),
    ("text", &["data"]),
    ("sent_at", &["timestamp"]),
    ("media_type", &["media_wa_type"]),
    ("media_size", &["media_size"]),
];

const LEGACY_REQUIRED_FIELDS: &[&str] = &["text", "sent_at", "from_me"];

/// The iOS `ZWAMESSAGE` entity.
const IOS_MESSAGE_FIELDS: &[(&str, &[&str])] = &[
    ("pk", &["Z_PK"]),
    ("text", &["ZTEXT"]),
    ("sent_at", &["ZMESSAGEDATE"]),
    ("from_me", &["ZISFROMME"]),
    ("message_type", &["ZMESSAGETYPE"]),
    ("starred", &["ZSTARRED"]),
    ("from_jid", &["ZFROMJID"]),
    ("to_jid", &["ZTOJID"]),
    ("chat_session", &["ZCHATSESSION"]),
];

const IOS_REQUIRED_FIELDS: &[&str] = &["text", "sent_at", "from_me"];

/// The map every parser writes its query from when the column list could not
/// be read: the schema this parser was written to, candidate by candidate.
/// The [`SchemaProbe`] has recorded that the list would not read, and its
/// marker says so; resolving against nothing instead would name every field as
/// "no column recognised", which is not what happened.
fn written_schema(specs: &[(&str, &[&str])]) -> FieldMap {
    let first: std::collections::HashSet<String> = specs
        .iter()
        .filter_map(|(_, c)| c.first())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    FieldMap::resolve(&first, specs)
}

/// Maximum number of messages to extract per database.
const MAX_MESSAGE_ENTRIES: usize = 500_000;

/// Maximum on-disk database size we will spill and open.
const MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Convert an Android Unix-millisecond timestamp to Unix seconds. Returns None
/// for NULL or the 0 sentinel so an unset timestamp never surfaces as
/// 1970-01-01.
fn android_millis_to_unix(ms: Option<i64>) -> Option<i64> {
    match ms {
        Some(m) if m != 0 => Some(m / 1000),
        _ => None,
    }
}

pub struct WhatsAppParser;

/// Identifies if a file is a WhatsApp database based on its name.
/// Permissive filename pre-filter (only decides whether to open the file). The
/// returned variant is a best guess from the name; the real variant is
/// confirmed by schema after opening, so renamed copies (e.g. `whatsapp_chat.db`)
/// are still parsed. Returns None only when the name gives no WhatsApp hint.
fn identify_whatsapp_db(name: &str) -> Option<WhatsAppVariant> {
    let n = name.to_ascii_lowercase();
    if n.ends_with("chatstorage.sqlite") {
        Some(WhatsAppVariant::Ios)
    } else if n.ends_with("msgstore.db") {
        Some(WhatsAppVariant::Android)
    } else if n.contains("whatsapp") {
        // Unknown platform from the name alone — schema detection decides.
        Some(WhatsAppVariant::Ios)
    } else {
        None
    }
}

/// True when the file NAME on its own identifies a WhatsApp message store,
/// rather than merely mentioning the app.
///
/// [`identify_whatsapp_db`] is deliberately permissive: anything whose name
/// contains "whatsapp" is opened, so a renamed copy is still parsed. That is the
/// right gate for *opening* a file and the wrong one for *asserting* that a file
/// was a chat database. A real Android or iOS extraction is full of
/// `whatsapp.log`, `com.whatsapp.apk`, `com.whatsapp_preferences.xml` — none of
/// them databases — and reporting each as a "WhatsApp Database (parse failed)"
/// would file a positive claim about a file this tool never had reason to think
/// was a store, and inflate the `metadata.$.type == "WhatsApp"` census with it.
/// `msgstore.db` and `ChatStorage.sqlite` name a store and nothing else, so a
/// file with one of those names that will not read IS worth declaring.
fn name_identifies_a_whatsapp_store(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("chatstorage.sqlite") || n.ends_with("msgstore.db")
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum WhatsAppVariant {
    Ios,
    Android,
}

impl WhatsAppVariant {
    fn label(&self) -> &'static str {
        match self {
            WhatsAppVariant::Ios => "WhatsApp (iOS)",
            WhatsAppVariant::Android => "WhatsApp (Android)",
        }
    }
}

/// The record type every WhatsApp incompleteness marker is filed under.
///
/// Never `"WhatsApp"`: `seance_db` groups conversations by `metadata.$.type`, so
/// a marker carrying the message type would be aggregated as a message and shown
/// as a phantom one-message conversation.
const INCOMPLETE_TYPE: &str = "WhatsAppIncomplete";

/// True if the staged copy begins with the SQLite file magic.
///
/// Used to tell "not our database" from "a WhatsApp store that would not read":
/// the first must stay on the identification path, the second must be reported
/// as an unreadable store. The filename gate is permissive enough
/// (`name.contains("whatsapp")`) that without this check any unrelated file with
/// "whatsapp" in its name could be reported as a chat database this tool failed
/// to examine.
fn staged_looks_like_sqlite(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && seance_core::io::is_sqlite_header(&head)
}

/// Whether the database carries the iOS WhatsApp (Core Data) schema.
///
/// Returns [`Presence`], not `bool`. This probe used to end in
/// `.unwrap_or(false)`, so a `sqlite_master` read that failed on a corrupt or
/// carved `ChatStorage.sqlite` gave the same answer as "this is not a WhatsApp
/// database" — and the caller then emitted no artifacts at all, which puts
/// **"this phone had no WhatsApp history"** in the case file (B8-015).
fn ios_schema_presence(conn: &Connection) -> Presence {
    probe_table(conn, "ZWAMESSAGE")
}

/// Whether the database carries an Android WhatsApp schema: `message` on newer
/// msgstore generations, `messages` on older ones.
///
/// A probe that could not be answered is only reported as undetermined when the
/// OTHER name did not answer `Present`: if `messages` is listed, this is an
/// Android WhatsApp store regardless of what the first probe did.
fn android_schema_presence(conn: &Connection) -> Presence {
    match probe_table(conn, "message") {
        Presence::Present => Presence::Present,
        Presence::Absent => probe_table(conn, "messages"),
        Presence::Undetermined(why) => match probe_table(conn, "messages") {
            Presence::Present => Presence::Present,
            _ => Presence::Undetermined(why),
        },
    }
}

// --- iOS WhatsApp parsing ---

/// Declared type of `column` in `table`, uppercased, or None when absent.
///
/// Takes the [`SchemaProbe`] so a `PRAGMA` that would not run is recorded rather
/// than spent as "no such column": reading the wrong `key_remote_jid` schema
/// generation drops every message in the store (B8-023).
fn column_decltype(
    probe: &mut SchemaProbe,
    conn: &Connection,
    table: &str,
    column: &str,
) -> Option<String> {
    probe
        .column_types(conn, table)
        .remove(&column.to_ascii_lowercase())
}

/// Storage class actually used by `column`'s first non-NULL row. Only consulted
/// when the column is declared without a type, where affinity coerces nothing
/// and the declared type therefore says nothing about the stored value.
///
/// An empty table answers `QueryReturnedNoRows`, which is a real answer ("no
/// non-NULL value to judge") and not a probe failure; anything else is recorded.
fn stored_type_is_integer(
    probe: &mut SchemaProbe,
    conn: &Connection,
    table: &str,
    column: &str,
) -> bool {
    match conn.query_row(
        &format!("SELECT typeof({column}) FROM {table} WHERE {column} IS NOT NULL LIMIT 1"),
        [],
        |row| row.get::<_, String>(0),
    ) {
        Ok(t) => t.eq_ignore_ascii_case("integer"),
        Err(rusqlite::Error::QueryReturnedNoRows) => false,
        Err(e) => {
            probe.record_failure(format!(
                "could not read the stored type of `{table}.{column}`: {e}"
            ));
            false
        }
    }
}

/// True when `column` holds integers: declared INTEGER affinity (SQLite rule:
/// declared type contains "INT"), or the stored storage class when no type is
/// declared. Distinguishes a numeric `key_remote_jid` FK (points at `jid._id`)
/// from a legacy string JID stored directly in the column.
fn column_is_integer(
    probe: &mut SchemaProbe,
    conn: &Connection,
    table: &str,
    column: &str,
) -> bool {
    match column_decltype(probe, conn, table, column) {
        Some(t) if t.trim().is_empty() => stored_type_is_integer(probe, conn, table, column),
        Some(t) => t.contains("INT"),
        None => false,
    }
}

/// Content type guessed from a media file's extension, for display only.
fn mime_from_path(path: &str) -> Option<&'static str> {
    let ext = path.rsplit('.').next()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "3gp" => "video/3gpp",
        "opus" => "audio/opus",
        "m4a" => "audio/mp4",
        "mp3" => "audio/mpeg",
        "aac" => "audio/aac",
        "pdf" => "application/pdf",
        _ => return None,
    })
}

/// Build one attachment artifact from a media row.
fn media_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    platform: &str,
    message_row: Option<i64>,
    local_path: &str,
    file_size: Option<i64>,
) -> Artifact {
    let base = local_path
        .rsplit('/')
        .next()
        .unwrap_or(local_path)
        .to_string();
    let metadata = json!({
        "type": "WhatsAppAttachment",
        "subtype": "chat_attachment",
        "platform": platform,
        // Source table this row was read from, for provenance.
        "source_table": if platform == "iOS" { "ZWAMEDIAITEM" } else { "message_media" },
        // The message this media belongs to, so the viewer can show it inline.
        "message_rowid": message_row,
        // Path as the app recorded it. The file resolver matches it against the
        // evidence by path suffix, since the app's path is relative to its own
        // container (WhatsApp says "Media/..." for "Message/Media/..." in a
        // backup).
        "filename": local_path,
        "transfer_name": base,
        "mime_type": mime_from_path(local_path),
        "total_bytes": file_size,
        "name": format!("Attachment: {}", base),
    });
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}

/// iOS WhatsApp media: ZWAMEDIAITEM carries the local path and links to its
/// message through ZMESSAGE.
fn parse_ios_media(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    parse_ios_media_capped(conn, case_id, parent_id, MAX_MESSAGE_ENTRIES)
}

/// [`parse_ios_media`] with the row budget supplied, so the cap-reached path is
/// reachable in a test.
fn parse_ios_media_capped(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Vec<Artifact> {
    // Tri-state, not `unwrap_or(false)`: a catalogue read that fails here would
    // otherwise say "this account sent and received no media", which is a claim
    // about the device drawn from a read error (B8-023).
    let mut probe = SchemaProbe::new();
    if !probe.has_table(conn, "ZWAMEDIAITEM") {
        // Counted as zero recovered: the marker exists precisely for the case
        // where nothing came back and nothing else would say why.
        return probe
            .marker(
                case_id,
                parent_id,
                "WhatsAppMediaIncomplete",
                "ZWAMEDIAITEM",
                0,
            )
            .into_iter()
            .collect();
    }
    let mut cap = CapCounter::new(max_entries);
    let mut stmt = match conn.prepare(
        "SELECT ZMESSAGE, ZMEDIALOCALPATH, ZFILESIZE FROM ZWAMEDIAITEM \
         WHERE ZMEDIALOCALPATH IS NOT NULL LIMIT ?1",
    ) {
        Ok(s) => s,
        // ZWAMEDIAITEM IS listed, so a query that will not run against it is a
        // damaged store — not an account that sent and received no media. A
        // `debug!` alone leaves the case saying the second (B8-023).
        Err(e) => {
            debug!("WhatsApp iOS media query unavailable: {}", e);
            probe.record_failure(format!("the `ZWAMEDIAITEM` query would not prepare: {e}"));
            return probe
                .marker(
                    case_id,
                    parent_id,
                    "WhatsAppMediaIncomplete",
                    "ZWAMEDIAITEM",
                    0,
                )
                .into_iter()
                .collect();
        }
    };
    let rows = match stmt.query_map([cap.limit()], |row| {
        Ok((
            row.get::<_, Option<i64>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<i64>>(2)?,
        ))
    }) {
        Ok(r) => r,
        Err(e) => {
            debug!("WhatsApp iOS media rows unavailable: {}", e);
            probe.record_failure(format!("the `ZWAMEDIAITEM` walk would not run: {e}"));
            return probe
                .marker(
                    case_id,
                    parent_id,
                    "WhatsAppMediaIncomplete",
                    "ZWAMEDIAITEM",
                    0,
                )
                .into_iter()
                .collect();
        }
    };
    let mut out = Vec::new();
    // Media rows that would not decode: each is an attachment this device held
    // and the case no longer lists (B3-023).
    let mut drops = RowDrops::new();
    for row in rows {
        let (msg, path, size) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skipping undecodable iOS WhatsApp media row: {}", e);
                drops.record(&e);
                continue;
            }
        };
        if !cap.admit() {
            break;
        }
        out.push(media_artifact(case_id, parent_id, "iOS", msg, &path, size));
    }
    // Records recovered, counted before any marker joins the list so the marker
    // never counts itself as a recovered record.
    let recovered = out.len();
    // A media inventory that stopped early must not read as "there was no more
    // media": the missing rows are attachments this device did hold.
    if cap.truncated() {
        out.push(cap_marker(
            case_id,
            parent_id,
            "WhatsAppMediaIncomplete",
            "ZWAMEDIAITEM",
            &cap,
        ));
    }
    out.extend(drops.marker(
        case_id,
        parent_id,
        "WhatsAppMediaIncomplete",
        "ZWAMEDIAITEM",
        recovered,
    ));
    out
}

/// Android WhatsApp media. Newer msgstore builds keep a `message_media` table
/// keyed by message row; older ones put the path on `message` itself. Both are
/// probed, so whichever the evidence has is used and neither is assumed.
fn parse_android_media(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    parse_android_media_capped(conn, case_id, parent_id, MAX_MESSAGE_ENTRIES)
}

/// [`parse_android_media`] with the row budget supplied, so the cap-reached path
/// is reachable in a test.
fn parse_android_media_capped(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Vec<Artifact> {
    let mut out = Vec::new();
    // Markers the modern-schema walk owes the examiner even when it recovered
    // nothing and the walk falls through to the legacy schema below. Held apart
    // from `out` so the legacy block's `recovered` count stays its own count of
    // media records and never includes a marker.
    let mut carried: Vec<Artifact> = Vec::new();
    // Every table/column question below goes through this, so a probe that could
    // not be answered is recorded instead of being spent as "the media table is
    // not there" (B8-023).
    let mut probe = SchemaProbe::new();

    let has_media_table = probe.has_table(conn, "message_media");
    if has_media_table && probe.has_column(conn, "message_media", "file_path") {
        let mut cap = CapCounter::new(max_entries);
        // `message_row_id` links media to its message and is an integer. When a
        // schema lacks it, bind NULL rather than a string column (`message_url`)
        // as the i64 rowid -- binding a string as i64 fails conversion for every
        // row, silently dropping all attachments.
        let key = if probe.has_column(conn, "message_media", "message_row_id") {
            "message_row_id"
        } else {
            "NULL"
        };
        let sql = format!(
            "SELECT {key}, file_path, file_size FROM message_media \
             WHERE file_path IS NOT NULL LIMIT ?1"
        );
        let mut drops = RowDrops::new();
        // `message_media` IS listed with a `file_path` column, so a query that
        // will not run against it is a damaged store, never "no attachments".
        // Recorded rather than silently skipped (B8-023).
        match conn.prepare(&sql) {
            Err(e) => {
                probe.record_failure(format!("the `message_media` query would not prepare: {e}"))
            }
            Ok(mut stmt) => match stmt.query_map([cap.limit()], |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            }) {
                Err(e) => {
                    probe.record_failure(format!("the `message_media` walk would not run: {e}"))
                }
                Ok(rows) => {
                    for row in rows {
                        let (msg, path, size) = match row {
                            Ok(r) => r,
                            Err(e) => {
                                debug!("Skipping undecodable message_media row: {}", e);
                                drops.record(&e);
                                continue;
                            }
                        };
                        if !cap.admit() {
                            break;
                        }
                        out.push(media_artifact(
                            case_id, parent_id, "Android", msg, &path, size,
                        ));
                    }
                }
            },
        }
        // Counted before any marker joins the list.
        let recovered = out.len();
        let undecodable = drops.marker(
            case_id,
            parent_id,
            "WhatsAppMediaIncomplete",
            "message_media",
            recovered,
        );
        if !out.is_empty() {
            if cap.truncated() {
                out.push(cap_marker(
                    case_id,
                    parent_id,
                    "WhatsAppMediaIncomplete",
                    "message_media",
                    &cap,
                ));
            }
            out.extend(undecodable);
            out.extend(probe.marker(
                case_id,
                parent_id,
                "WhatsAppMediaIncomplete",
                "message_media",
                recovered,
            ));
            return out;
        }
        // Nothing decoded. The walk falls through to the legacy schema, but the
        // rows it could not decode are attachments this device held: without
        // the marker they leave no trace at all, and an examiner reads "no
        // media" for a phone whose media table was unreadable (B3-023).
        carried.extend(undecodable);
    }

    // Older schema: the media path hangs off the message row itself.
    if probe.has_table(conn, "message") && probe.has_column(conn, "message", "media_name") {
        let mut cap = CapCounter::new(max_entries);
        let sql = "SELECT _id, media_name, media_size FROM message \
                   WHERE media_name IS NOT NULL AND media_name <> '' LIMIT ?1";
        let mut drops = RowDrops::new();
        // Same rule on the legacy schema: `message.media_name` was probed and
        // found, so a query that will not run is a damaged store.
        match conn.prepare(sql) {
            Err(e) => probe.record_failure(format!(
                "the legacy `message` media query would not prepare: {e}"
            )),
            Ok(mut stmt) => match stmt.query_map([cap.limit()], |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            }) {
                Err(e) => probe.record_failure(format!(
                    "the legacy `message` media walk would not run: {e}"
                )),
                Ok(rows) => {
                    for row in rows {
                        let (msg, path, size) = match row {
                            Ok(r) => r,
                            Err(e) => {
                                debug!("Skipping undecodable legacy media row: {}", e);
                                drops.record(&e);
                                continue;
                            }
                        };
                        if !cap.admit() {
                            break;
                        }
                        out.push(media_artifact(
                            case_id, parent_id, "Android", msg, &path, size,
                        ));
                    }
                }
            },
        }
        {
            let recovered = out.len();
            out.extend(drops.marker(
                case_id,
                parent_id,
                "WhatsAppMediaIncomplete",
                "message",
                recovered,
            ));
        }
        if cap.truncated() {
            out.push(cap_marker(
                case_id,
                parent_id,
                "WhatsAppMediaIncomplete",
                "message",
                &cap,
            ));
        }
    }
    out.extend(carried);
    // Counted before the schema marker joins the list, and only over media
    // records, so the marker never counts itself or another marker.
    let media_recovered = out
        .iter()
        .filter(|a| a.metadata["type"] == json!("WhatsAppAttachment"))
        .count();
    out.extend(probe.marker(
        case_id,
        parent_id,
        "WhatsAppMediaIncomplete",
        "message_media",
        media_recovered,
    ));
    out
}

fn parse_ios_messages(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Result<Vec<Artifact>> {
    parse_ios_messages_capped(conn, case_id, parent_id, MAX_MESSAGE_ENTRIES)
}

/// [`parse_ios_messages`] with the row budget supplied, so the cap-reached path
/// is reachable in a test without seeding half a million messages.
fn parse_ios_messages_capped(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let mut cap = CapCounter::new(max_entries);
    // Rows the walk fetches and cannot decode. Counted, because `continue`
    // alone makes them vanish and the message count then reads as exact (B3-023).
    let mut drops = RowDrops::new();

    // Optional-table probes. A probe that ERRORS is not "the table is absent":
    // answering `false` for ZWACHATSESSION drops the correspondent's identity
    // from every message, and the conversation then reads as one with an unknown
    // party rather than one this tool could not resolve (B8-023).
    let mut probe = SchemaProbe::new();
    let has_chat = probe.has_table(conn, "ZWACHATSESSION");
    let has_pushname = probe.has_table(conn, "ZWAPROFILEPUSHNAME");

    // Every ZWAMESSAGE column is read through the field map, so a renamed one
    // is substituted as NULL AND recorded, instead of failing `prepare()` and
    // turning the whole store into a "parse failed" stub.
    let cols = probe.columns(conn, "ZWAMESSAGE");
    let fields = if cols.is_empty() {
        written_schema(IOS_MESSAGE_FIELDS)
    } else {
        FieldMap::resolve(&cols, IOS_MESSAGE_FIELDS)
    };
    let pk_col = field_expr(&fields, "m", "pk");
    let pk_col = if pk_col == "NULL" { "m.rowid" } else { &pk_col };
    let text_col = field_expr(&fields, "m", "text");
    let date_col = field_expr(&fields, "m", "sent_at");
    let from_me_col = field_expr(&fields, "m", "from_me");
    let type_col = field_expr(&fields, "m", "message_type");
    let starred_col = field_expr(&fields, "m", "starred");
    let from_jid_col = field_expr(&fields, "m", "from_jid");
    let to_jid_col = field_expr(&fields, "m", "to_jid");
    let order_col = if date_col == "NULL" {
        pk_col
    } else {
        &date_col
    };

    // The joins need the columns they join on; a join on NULL is dropped, and
    // the map has recorded the field it would have needed.
    let (session_join, session_cols) = if has_chat && fields.column("chat_session").is_some() {
        let session_col = field_expr(&fields, "m", "chat_session");
        (
            format!("LEFT JOIN ZWACHATSESSION cs ON {session_col} = cs.Z_PK"),
            "cs.ZCONTACTJID, cs.ZPARTNERNAME, cs.ZSESSIONTYPE",
        )
    } else {
        (
            String::new(),
            "NULL AS ZCONTACTJID, NULL AS ZPARTNERNAME, NULL AS ZSESSIONTYPE",
        )
    };
    let (pushname_join, pushname_col) = if has_pushname && from_jid_col != "NULL" {
        (
            format!("LEFT JOIN ZWAPROFILEPUSHNAME pn ON {from_jid_col} = pn.ZJID"),
            "pn.ZPUSHNAME",
        )
    } else {
        (String::new(), "NULL AS ZPUSHNAME")
    };

    let query = format!(
        "SELECT {pk_col}, {text_col}, {date_col}, {from_me_col}, {type_col}, \
                {starred_col}, {from_jid_col}, {to_jid_col}, \
                {session_cols}, {pushname_col} \
         FROM ZWAMESSAGE m \
         {session_join} {pushname_join} \
         ORDER BY {order_col} DESC \
         LIMIT ?1"
    );

    let mut stmt = conn
        .prepare(&query)
        .context("Failed to prepare iOS WhatsApp query")?;

    let rows = stmt
        .query_map([cap.limit()], |row| {
            Ok((
                row.get::<_, i64>(0)?,             // Z_PK
                row.get::<_, Option<String>>(1)?,  // ZTEXT
                row.get::<_, Option<f64>>(2)?,     // ZMESSAGEDATE (can be float)
                row.get::<_, Option<i64>>(3)?,     // ZISFROMME
                row.get::<_, Option<i64>>(4)?,     // ZMESSAGETYPE
                row.get::<_, Option<i64>>(5)?,     // ZSTARRED
                row.get::<_, Option<String>>(6)?,  // ZFROMJID
                row.get::<_, Option<String>>(7)?,  // ZTOJID
                row.get::<_, Option<String>>(8)?,  // ZCONTACTJID
                row.get::<_, Option<String>>(9)?,  // ZPARTNERNAME
                row.get::<_, Option<i64>>(10)?,    // ZSESSIONTYPE
                row.get::<_, Option<String>>(11)?, // ZPUSHNAME
            ))
        })
        .context("Failed to query iOS WhatsApp messages")?;

    for row in rows {
        if !cap.admit() {
            break;
        }
        let (
            pk,
            text,
            message_date,
            is_from_me,
            message_type,
            starred,
            from_jid,
            to_jid,
            contact_jid,
            partner_name,
            session_type,
            push_name,
        ) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skipping malformed iOS WhatsApp row: {}", e);
                drops.record(&e);
                continue;
            }
        };

        // ZMESSAGEDATE is seconds since 2001-01-01 (Core Data epoch); NULL/0
        // stays absent instead of surfacing as a fabricated 2001/1970 date.
        //
        // The column is REAL and the fraction is evidence: messages inside one
        // second are ordered only by it, and `seance_db` reads `date_ns` off
        // this record to fill `timeline_events.timestamp_subsec_nanos`. Decoded
        // through the whole-seconds helper, a reply used to be able to sort
        // ahead of the message it answered.
        let date_parts = message_date.and_then(cocoa_secs_to_unix_nanos);
        let unix_timestamp = date_parts.map(|(secs, _)| secs);

        // A NULL ZISFROMME means the direction was never recorded (corrupt or
        // partially recovered row): report it as unknown rather than asserting
        // "received", which would silently invert an outgoing message.
        let is_sent = is_from_me.map(|v| v != 0);
        let direction = is_sent.map(|s| if s { "sent" } else { "received" });

        // The remote party's JID. WhatsApp records the peer of a *sent* message
        // in ZTOJID and leaves ZFROMJID NULL (the sender is the device owner),
        // so reading ZFROMJID first reports the peer as Unknown — or, where the
        // column is populated, as the owner themselves. ZCONTACTJID (the chat
        // session) resolves either direction when the message-level column is
        // NULL; the far end of an outgoing message is never ZFROMJID, and the
        // far end of an incoming one is never ZTOJID, so neither is used as a
        // fallback for the other.
        let remote_jid: Option<&str> = match is_sent {
            Some(true) => to_jid.as_deref().or(contact_jid.as_deref()),
            Some(false) => from_jid.as_deref().or(contact_jid.as_deref()),
            None => contact_jid
                .as_deref()
                .or(from_jid.as_deref())
                .or(to_jid.as_deref()),
        };

        // ZPUSHNAME is joined on ZFROMJID, so it names whoever sent the row. It
        // is the peer's name only when the peer is the sender.
        let remote_push_name = push_name
            .as_deref()
            .filter(|_| remote_jid.is_some() && remote_jid == from_jid.as_deref());

        // Determine contact: session partner name, the remote's push name, then
        // the remote JID itself.
        let contact = partner_name
            .as_deref()
            .or(remote_push_name)
            .or(remote_jid)
            .unwrap_or("Unknown");

        // Parse JID to get phone number
        let phone = extract_phone_from_jid(remote_jid.unwrap_or(""));

        let is_group = session_type.unwrap_or(0) == 2
            || contact_jid
                .as_deref()
                .map(|j| j.contains("@g.us"))
                .unwrap_or(false);

        let text_preview = text
            .as_deref()
            .unwrap_or("")
            .chars()
            .take(80)
            .collect::<String>();

        let name = format!(
            "{}: {} — {}",
            direction.unwrap_or("message"),
            contact,
            if text_preview.is_empty() {
                "(media)"
            } else {
                &text_preview
            },
        );

        let contact_name = partner_name
            .as_deref()
            .or(remote_push_name)
            .map(|s| s.to_string());
        // `contact` borrows the JID options, so it must be owned before they are
        // moved into the metadata below.
        let contact = contact.to_string();
        let remote_jid = remote_jid.map(|s| s.to_string());

        let mut metadata = json!({
            "type": "WhatsApp",
            "subtype": "chat_message",
            "platform": "iOS",
            "source_table": "ZWAMESSAGE",
            "pk": pk,
            "text": text,
            "date": unix_timestamp,
            "is_from_me": is_sent,
            "direction": direction,
            "message_type": message_type,
            "starred": starred.unwrap_or(0) != 0,
            "from_jid": from_jid,
            "to_jid": to_jid,
            "contact_jid": contact_jid,
            // The party at the other end of this message, whichever column
            // carried it, so the viewer and the connections graph agree.
            "remote_jid": remote_jid,
            "contact": contact,
            "contact_name": contact_name,
            "phone_number": phone,
            "is_group": is_group,
            "session_type": session_type,
            "name": name,
        });

        // Full-precision instant beside the whole seconds, in the same
        // `<field>_ns` shape the iMessage parser publishes — it is what carries
        // the ZMESSAGEDATE fraction onto the unified timeline. Absent when the
        // message landed exactly on a second, because there is then nothing the
        // seconds field does not already say.
        if let Some(ns) = date_parts.and_then(|(secs, nanos)| unix_ns(secs, nanos)) {
            metadata["date_ns"] = json!(ns);
        }

        let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(parent_id)
            .with_subtype("chat_message");

        artifacts.push(artifact);
    }

    // Newest-first, so the cap drops the OLDEST messages — the start of the
    // conversation. Left unsaid, the surviving slice reads as the whole chat.
    if cap.truncated() {
        artifacts.push(cap_marker(
            case_id,
            parent_id,
            "WhatsAppIncomplete",
            "ZWAMESSAGE",
            &cap,
        ));
    }

    // Rows the walk fetched and could not decode. Without this the count above
    // is presented as the whole conversation (B3-023).
    {
        // Counted before the marker is appended, so it never counts itself.
        let recovered = artifacts
            .iter()
            .filter(|a| a.metadata["subtype"] == json!("chat_message"))
            .count();
        artifacts.extend(drops.marker(
            case_id,
            parent_id,
            "WhatsAppIncomplete",
            "ZWAMESSAGE",
            recovered,
        ));
        // Schema questions this parse could not answer. Without it, a query
        // built with the chat-session join silently dropped presents as a
        // complete conversation whose participants were simply never recorded.
        artifacts.extend(probe.marker(
            case_id,
            parent_id,
            INCOMPLETE_TYPE,
            "ZWAMESSAGE",
            recovered,
        ));
        // What this parser may say about the schema it just read: no range
        // (see `IOS_SCHEMA_SUPPORT`), the version not read (Core Data), and
        // any field the map could not resolve, named.
        artifacts.extend(
            SchemaCheck {
                support: &IOS_SCHEMA_SUPPORT,
                version: IOS_VERSION_NOT_READ,
                fields: &fields,
                required: IOS_REQUIRED_FIELDS,
                record_type: INCOMPLETE_TYPE,
                store: "ZWAMESSAGE",
            }
            .marker(case_id, parent_id, recovered),
        );
    }

    Ok(artifacts)
}

// --- Android WhatsApp parsing ---

/// Parse Android WhatsApp msgstore.db.
fn parse_android_messages(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
) -> Result<Vec<Artifact>> {
    parse_android_messages_capped(conn, case_id, parent_id, MAX_MESSAGE_ENTRIES)
}

/// [`parse_android_messages`] with the row budget supplied, so the cap-reached
/// path is reachable in a test.
fn parse_android_messages_capped(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    parse_android_messages_with(
        conn,
        case_id,
        parent_id,
        max_entries,
        &ANDROID_SCHEMA_SUPPORT,
    )
}

/// [`parse_android_messages_capped`] under an explicit schema declaration, so
/// the out-of-range paths are reachable in a test while the crate's own
/// declaration stays Unranged.
fn parse_android_messages_with(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
    support: &SchemaSupport,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let mut cap = CapCounter::new(max_entries);
    // Rows the walk fetches and cannot decode. Counted, because `continue`
    // alone makes them vanish and the message count then reads as exact (B3-023).
    let mut drops = RowDrops::new();

    // Schema-generation probes. Each one used to end in `.unwrap_or(false)`,
    // which answers "the catalogue would not read" with "the table is not
    // there": the query is then built without the `jid` join and every message
    // loses its correspondent, or the walk falls through to the legacy schema
    // and finds nothing — both presented as a complete parse (B8-023).
    let mut probe = SchemaProbe::new();
    let has_message = probe.has_table(conn, "message");
    let has_jid = probe.has_table(conn, "jid");
    let has_chat = probe.has_table(conn, "chat");

    // The field map this store's query was written from, for the schema
    // record at the end.
    let fields: FieldMap;
    let required: &[&str];

    if has_message {
        // Newer Android WhatsApp schema. Column names and the JID linkage differ
        // across msgstore generations, so resolve them through the field map
        // instead of hardcoding the legacy names (which yields zero messages on
        // modern evidence):
        //   text:    `text_data` (modern) | `data` (legacy `message`)
        //   from_me: `from_me`   (modern) | `key_from_me` (legacy)
        //   JID:     `chat_row_id` -> chat._id -> chat.jid_row_id -> jid._id
        //            (modern) | `key_remote_jid` as an integer FK to jid._id
        //            (transitional) | `key_remote_jid` as a string JID (legacy).
        // A column no candidate matches is substituted as NULL and RECORDED, so
        // a renamed `from_me` can no longer make every message direction-unknown
        // with nothing on the record saying so.
        let cols = probe.columns(conn, "message");
        // When the column list would not read, `probe` has recorded it and its
        // marker says the schema is undetermined; the map is then resolved
        // against nothing and nothing is required of it, because "no column
        // recognised" is not what happened.
        let columns_read = !cols.is_empty();
        fields = FieldMap::resolve(
            &cols,
            if columns_read {
                ANDROID_MESSAGE_FIELDS
            } else {
                &[]
            },
        );
        required = if columns_read {
            ANDROID_REQUIRED_FIELDS
        } else {
            &[]
        };
        let text_col = field_expr(&fields, "m", "text");
        let from_me_col = field_expr(&fields, "m", "from_me");
        let key_id_col = field_expr(&fields, "m", "key_id");
        let status_col = field_expr(&fields, "m", "status");
        let media_type_col = field_expr(&fields, "m", "media_type");
        let media_size_col = field_expr(&fields, "m", "media_size");
        let starred_col = field_expr(&fields, "m", "starred");
        // `timestamp` was always named outright; it still is when the column
        // list could not be read, so that case parses exactly as it did.
        let ts_col = if columns_read {
            field_expr(&fields, "m", "sent_at")
        } else {
            "m.timestamp".to_string()
        };
        let order_col = if ts_col == "NULL" { "m._id" } else { &ts_col };

        let has_chat_row_id = probe.has_column(conn, "message", "chat_row_id");
        let has_key_remote_jid = probe.has_column(conn, "message", "key_remote_jid");
        let chat_has_jid_row_id = has_chat && probe.has_column(conn, "chat", "jid_row_id");
        let chat_has_jid = has_chat && probe.has_column(conn, "chat", "jid");
        let chat_has_subject = has_chat && probe.has_column(conn, "chat", "subject");
        let key_remote_jid_is_int =
            has_key_remote_jid && column_is_integer(&mut probe, conn, "message", "key_remote_jid");

        // `chat.subject` is absent on some generations; selecting it blindly
        // makes prepare() fail, which drops the whole database to a ParseFailed
        // stub instead of losing only the group subject.
        let subject_col = if chat_has_subject {
            "c.subject"
        } else {
            "NULL"
        };

        let (join_sql, jid_expr, subject_expr): (String, &str, &str) =
            if has_chat_row_id && chat_has_jid_row_id && has_jid {
                // Modern: message.chat_row_id -> chat._id, chat.jid_row_id -> jid._id.
                (
                    "LEFT JOIN chat c ON m.chat_row_id = c._id \
                     LEFT JOIN jid j ON c.jid_row_id = j._id"
                        .to_string(),
                    "j.raw_string",
                    subject_col,
                )
            } else if key_remote_jid_is_int && has_jid {
                // Transitional: key_remote_jid is an integer FK into jid._id.
                let (cjoin, subj) = if chat_has_jid_row_id {
                    (
                        "LEFT JOIN chat c ON c.jid_row_id = m.key_remote_jid",
                        subject_col,
                    )
                } else {
                    ("", "NULL")
                };
                (
                    format!("LEFT JOIN jid j ON j._id = m.key_remote_jid {cjoin}"),
                    "j.raw_string",
                    subj,
                )
            } else if has_key_remote_jid && !key_remote_jid_is_int && has_jid && chat_has_jid {
                // Legacy string `message` schema: key_remote_jid is the string JID.
                (
                    "LEFT JOIN jid j ON m.key_remote_jid = j.raw_string \
                     LEFT JOIN chat c ON m.key_remote_jid = c.jid"
                        .to_string(),
                    "j.raw_string",
                    subject_col,
                )
            } else if has_key_remote_jid && !key_remote_jid_is_int {
                // No jid/chat lookup tables: the string JID lives on the message.
                (String::new(), "m.key_remote_jid", "NULL")
            } else {
                // Either no JID column at all, or an integer key_remote_jid with
                // no `jid` table to resolve it. Report the JID as absent rather
                // than surfacing a row id as a contact -- and rather than
                // selecting an integer into a String, which would fail decode on
                // every row and silently drop the entire conversation.
                (String::new(), "NULL", "NULL")
            };

        // Group chats: the chat JID identifies the *group*, not the person who
        // sent a received message. Modern msgstore keeps that in
        // `message.sender_jid_row_id` -> `jid._id` (NULL for 1:1 chats and for
        // own messages), so resolve it through a second `jid` join.
        let has_sender_jid_row_id = probe.has_column(conn, "message", "sender_jid_row_id");
        // Probe the jid columns too: naming one the schema lacks fails prepare()
        // and collapses the whole database to a ParseFailed stub.
        let jid_lookup_usable = has_jid
            && probe.has_column(conn, "jid", "_id")
            && probe.has_column(conn, "jid", "raw_string");
        let (sender_join, sender_expr) = if has_sender_jid_row_id && jid_lookup_usable {
            (
                " LEFT JOIN jid sj ON m.sender_jid_row_id = sj._id",
                "sj.raw_string",
            )
        } else {
            ("", "NULL")
        };

        let query = format!(
            "SELECT m._id, {key_id_col}, {text_col}, {ts_col}, {from_me_col}, \
                    {status_col}, {media_type_col}, {media_size_col}, {starred_col}, \
                    {jid_expr} AS jid_string, {subject_expr} AS chat_subject, \
                    {sender_expr} AS sender_jid \
             FROM message m \
             {join_sql}{sender_join} \
             ORDER BY {order_col} DESC \
             LIMIT ?1"
        );

        let mut stmt = conn
            .prepare(&query)
            .context("Failed to prepare Android WhatsApp query")?;

        let rows = stmt
            .query_map([cap.limit()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,             // _id
                    row.get::<_, Option<String>>(1)?,  // key_id
                    row.get::<_, Option<String>>(2)?,  // data (message text)
                    row.get::<_, Option<i64>>(3)?,     // timestamp (ms)
                    row.get::<_, Option<i64>>(4)?,     // key_from_me
                    row.get::<_, Option<i64>>(5)?,     // status
                    row.get::<_, Option<i64>>(6)?,     // media_wa_type
                    row.get::<_, Option<i64>>(7)?,     // media_size
                    row.get::<_, Option<i64>>(8)?,     // starred
                    row.get::<_, Option<String>>(9)?,  // jid_string
                    row.get::<_, Option<String>>(10)?, // chat_subject
                    row.get::<_, Option<String>>(11)?, // sender_jid (group sender)
                ))
            })
            .context("Failed to query Android WhatsApp messages")?;

        for row in rows {
            if !cap.admit() {
                break;
            }
            let (
                id,
                key_id,
                data,
                timestamp_ms,
                key_from_me,
                status,
                media_wa_type,
                media_size,
                starred,
                jid_string,
                chat_subject,
                sender_jid,
            ) = match row {
                Ok(r) => r,
                Err(e) => {
                    debug!("Skipping malformed Android WhatsApp row: {}", e);
                    drops.record(&e);
                    continue;
                }
            };

            // Android timestamps are milliseconds since Unix epoch; NULL/0
            // stays absent instead of surfacing as a fabricated 1970 date.
            let unix_timestamp = android_millis_to_unix(timestamp_ms);

            // A NULL / absent from-me column means the direction was never
            // recorded: keep it unknown rather than asserting "received".
            let is_sent = key_from_me.map(|v| v != 0);
            let direction = is_sent.map(|s| if s { "sent" } else { "received" });

            let contact = chat_subject
                .as_deref()
                .or(jid_string.as_deref())
                .unwrap_or("Unknown");
            let phone = extract_phone_from_jid(jid_string.as_deref().unwrap_or(""));
            // Who actually sent a received group message (absent on 1:1 chats
            // and on own messages, where the chat JID already says it).
            let sender_phone = extract_phone_from_jid(sender_jid.as_deref().unwrap_or(""));

            let is_group = jid_string
                .as_deref()
                .map(|j| j.contains("@g.us"))
                .unwrap_or(false);

            let text_preview = data
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(80)
                .collect::<String>();

            let name = format!(
                "{}: {} — {}",
                direction.unwrap_or("message"),
                contact,
                if text_preview.is_empty() {
                    "(media)"
                } else {
                    &text_preview
                },
            );

            let metadata = json!({
                "type": "WhatsApp",
                "subtype": "chat_message",
                "platform": "Android",
                "id": id,
                "key_id": key_id,
                "text": data,
                "date": unix_timestamp,
                "timestamp_ms": timestamp_ms,
                "is_from_me": is_sent,
                "direction": direction,
                "status": status,
                "media_type": media_wa_type,
                "media_size": media_size,
                "starred": starred.unwrap_or(0) != 0,
                "remote_jid": jid_string,
                "chat_subject": chat_subject,
                "phone_number": phone,
                "sender_jid": sender_jid,
                "sender_phone": sender_phone,
                "is_group": is_group,
                "name": name,
            });

            let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(parent_id)
                .with_subtype("chat_message");

            artifacts.push(artifact);
        }
    } else {
        // Legacy 'messages' table, read through its own map for the same
        // reason: a renamed column is named, not a failed `prepare()`.
        let cols = probe.columns(conn, "messages");
        let columns_read = !cols.is_empty();
        fields = FieldMap::resolve(
            &cols,
            if columns_read {
                LEGACY_MESSAGE_FIELDS
            } else {
                &[]
            },
        );
        required = if columns_read {
            LEGACY_REQUIRED_FIELDS
        } else {
            &[]
        };
        let (id_col, ts_col) = if columns_read {
            (
                fields.column("id").unwrap_or("rowid").to_string(),
                field_expr(&fields, "", "sent_at"),
            )
        } else {
            ("_id".to_string(), "timestamp".to_string())
        };
        let jid_col = field_expr(&fields, "", "remote_jid");
        let from_me_col = field_expr(&fields, "", "from_me");
        let text_col = field_expr(&fields, "", "text");
        let media_type_col = field_expr(&fields, "", "media_type");
        let media_size_col = field_expr(&fields, "", "media_size");
        let order_col = if ts_col == "NULL" { &id_col } else { &ts_col };
        let query = format!(
            "SELECT {id_col}, {jid_col}, {from_me_col}, {text_col}, {ts_col}, {media_type_col}, \
                    {media_size_col} \
             FROM messages \
             ORDER BY {order_col} DESC \
             LIMIT ?1"
        );
        let mut stmt = conn
            .prepare(&query)
            .context("Failed to prepare legacy Android WhatsApp query")?;

        let rows = stmt
            .query_map([cap.limit()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })
            .context("Failed to query legacy Android WhatsApp")?;

        for row in rows {
            if !cap.admit() {
                break;
            }
            let (id, remote_jid, key_from_me, data, timestamp_ms, media_type, media_size) =
                match row {
                    Ok(r) => r,
                    Err(e) => {
                        debug!("Skipping malformed legacy WhatsApp row: {}", e);
                        drops.record(&e);
                        continue;
                    }
                };

            // NULL/0 stays absent instead of surfacing as a fabricated 1970 date.
            let unix_timestamp = android_millis_to_unix(timestamp_ms);
            // A NULL `key_from_me` never recorded a direction: unknown, not
            // "received".
            let is_sent = key_from_me.map(|v| v != 0);
            let direction = is_sent.map(|s| if s { "sent" } else { "received" });
            let contact = remote_jid.as_deref().unwrap_or("Unknown");
            let text_preview = data
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(80)
                .collect::<String>();

            let metadata = json!({
                "type": "WhatsApp",
                "subtype": "chat_message",
                "platform": "Android",
                "id": id,
                "text": data,
                "date": unix_timestamp,
                "timestamp_ms": timestamp_ms,
                "is_from_me": is_sent,
                "direction": direction,
                "remote_jid": remote_jid,
                "phone_number": extract_phone_from_jid(contact),
                "is_group": contact.contains("@g.us"),
                "media_type": media_type,
                "media_size": media_size,
                "name": format!("{}: {} — {}", direction.unwrap_or("message"), contact,
                    if text_preview.is_empty() { "(media)" } else { &text_preview }),
            });

            let artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                .with_parent(parent_id)
                .with_subtype("chat_message");

            artifacts.push(artifact);
        }
    }

    // Both Android schemas order newest-first, so the cap drops the oldest
    // messages. The marker is the only thing that keeps the remainder from
    // being read as the complete message store.
    if cap.truncated() {
        let table = if has_message { "message" } else { "messages" };
        artifacts.push(cap_marker(
            case_id,
            parent_id,
            "WhatsAppIncomplete",
            table,
            &cap,
        ));
    }

    // Rows the walk fetched and could not decode (B3-023).
    {
        let table = if has_message { "message" } else { "messages" };
        // Counted before the marker is appended, so it never counts itself.
        let recovered = artifacts
            .iter()
            .filter(|a| a.metadata["subtype"] == json!("chat_message"))
            .count();
        artifacts.extend(drops.marker(case_id, parent_id, "WhatsAppIncomplete", table, recovered));
        // Schema questions this parse could not answer. A msgstore whose column
        // list would not read still runs its SELECT — with NULL substituted for
        // the text, the direction, or the JID join — and without this the result
        // presents as a complete conversation that simply had none of those.
        artifacts.extend(probe.marker(case_id, parent_id, INCOMPLETE_TYPE, table, recovered));
        // What this parser may say about the schema it just read: no range
        // (see `ANDROID_SCHEMA_SUPPORT`), the version the store carries, and
        // any field the map could not resolve, named.
        artifacts.extend(
            SchemaCheck {
                support,
                version: user_version(conn),
                fields: &fields,
                required,
                record_type: INCOMPLETE_TYPE,
                store: table,
            }
            .marker(case_id, parent_id, recovered),
        );
    }

    Ok(artifacts)
}

/// Extract phone number from a WhatsApp JID (e.g., "15551234567@s.whatsapp.net" -> "15551234567").
fn extract_phone_from_jid(jid: &str) -> Option<String> {
    if jid.is_empty() {
        return None;
    }
    jid.split('@')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

impl ForensicsModule for WhatsAppParser {
    fn id(&self) -> &str {
        "plugin.messaging.whatsapp"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::SystemArtifact]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        // An encrypted backup (`*.cryptNN`) or the key file that opens one.
        if let Some(records) = backup::route(self, artifact) {
            return Ok(records);
        }

        let variant = match identify_whatsapp_db(name) {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };

        info!(
            "WhatsAppParser processing {} database: {}",
            variant.label(),
            name
        );

        // A directory entry that carries the store's name is not a store, and
        // is not declared as one (ROADMAP §5.11: the shared entry gate).
        if seance_sqlite_util::is_directory_entry(artifact) {
            return Ok(Vec::new());
        }
        if artifact.data.is_none() {
            // No bytes to open. A name that only mentions the app — the
            // `com.whatsapp` app directory, a `WhatsApp Images` media
            // folder — was a reason to try opening a file, not a database
            // to declare; declaring it filed twenty-six "iOS databases"
            // on an Android image (HUNT-070). Only a name that IS a store's
            // name is worth a record without bytes, and it is declared by
            // the platform that name belongs to.
            if !name_identifies_a_whatsapp_store(name) {
                return Ok(Vec::new());
            }
            info!(
                "No data source for {}, producing identification artifact only",
                name
            );
            let metadata = json!({
                "type": "WhatsApp",
                "platform": format!("{:?}", variant),
                "file_name": name,
                "status": "Identified",
                "name": format!("{} Database (not parsed - no data): {}", variant.label(), name),
            });
            let id_artifact =
                Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(artifact.id);
            return Ok(vec![id_artifact]);
        }

        // Through the shared gate: a header that did not arrive in full is the
        // stager's record of a short read, never a finding about the file.
        let temp = match seance_sqlite_util::stage_named_store(artifact, "whatsapp", MAX_DB_BYTES) {
            Ok(Ok(temp)) => temp,
            Ok(Err(records)) => return Ok(records),
            Err(e) => {
                return Err(ModuleError::ParsingError(format!(
                    "Failed to extract DB: {}",
                    e
                )))
            }
        };

        let result = (|| -> Result<Vec<Artifact>> {
            let conn = temp.open().context("Failed to open WhatsApp database")?;

            // Before any absence is treated as a fact about the phone, establish
            // that the catalogue can be read at all. A carved or partially
            // recovered msgstore answers every `sqlite_master` query with
            // SQLITE_CORRUPT, and the probes below used to spend that as "not a
            // WhatsApp schema" and return nothing — which reads, in the report,
            // as a phone with no WhatsApp history (B8-015).
            if let Err(why) = seance_sqlite_util::probe_catalogue(&conn) {
                // Only claim a WhatsApp store was present when the staged bytes
                // really are a database. The filename gate here is permissive
                // (any name containing "whatsapp"), so a non-SQLite file must
                // not be reported as an unreadable chat store.
                if !staged_looks_like_sqlite(temp.path()) {
                    // A file NAMED for a store (`msgstore.db` /
                    // `ChatStorage.sqlite`) that is not a database is worth the
                    // existing ParseFailed identification. Anything else merely
                    // mentions WhatsApp in its name — a log, an APK, a
                    // preferences plist — and asserting a failed chat-database
                    // parse for it manufactures the opposite error to the one
                    // this branch exists to prevent, once per such file, under
                    // the `WhatsApp` record type the census groups on.
                    if !name_identifies_a_whatsapp_store(name) {
                        debug!("{name} mentions WhatsApp but is not a database: {why}");
                        return Ok(Vec::new());
                    }
                    anyhow::bail!("{name} is not a SQLite database: {why}");
                }
                return Ok(vec![unreadable_store_marker(
                    artifact.case_id,
                    artifact.id,
                    INCOMPLETE_TYPE,
                    format!(
                        "`{name}` carries the SQLite header and its schema catalogue would not \
                         read, so whether this device held WhatsApp messages is undetermined \
                         rather than answered: {why}"
                    ),
                )]);
            }

            // Confirm the actual variant by schema (the name-based guess may be
            // wrong for renamed databases). iOS and Android schemas are distinct.
            let ios = ios_schema_presence(&conn);
            let android = android_schema_presence(&conn);
            let actual = if ios.is_present() {
                Some(WhatsAppVariant::Ios)
            } else if android.is_present() {
                Some(WhatsAppVariant::Android)
            } else {
                None
            };
            let _ = variant; // name guess superseded by schema detection
            match actual {
                Some(WhatsAppVariant::Ios) => {
                    parse_ios_messages(&conn, artifact.case_id, artifact.id).map(|mut a| {
                        a.extend(parse_ios_media(&conn, artifact.case_id, artifact.id));
                        a
                    })
                }
                Some(WhatsAppVariant::Android) => {
                    parse_android_messages(&conn, artifact.case_id, artifact.id).map(|mut a| {
                        a.extend(parse_android_media(&conn, artifact.case_id, artifact.id));
                        a
                    })
                }
                // Neither schema is present. "The catalogue says this is not a
                // WhatsApp database" and "the catalogue would not say" are
                // opposite findings, and only the first may be answered with
                // silence.
                None => match ios
                    .undetermined_reason()
                    .or_else(|| android.undetermined_reason())
                {
                    Some(why) => Ok(vec![unreadable_store_marker(
                        artifact.case_id,
                        artifact.id,
                        INCOMPLETE_TYPE,
                        format!(
                            "`{name}` opened as SQLite and its message tables could not be \
                             looked for, so whether it holds a WhatsApp schema is undetermined \
                             rather than answered: {why}"
                        ),
                    )]),
                    None => {
                        info!("{} has no recognizable WhatsApp schema, skipping", name);
                        Ok(Vec::new())
                    }
                },
            }
        })();

        match result {
            Ok(mut artifacts) => {
                // A msgstore staged short (over the byte cap, or a source that
                // could not deliver its declared bytes) still opens and answers
                // queries: without this, the rows that survived read as the
                // whole chat history.
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!(
                    "WhatsAppParser extracted {} records from {} ({})",
                    artifacts.len(),
                    name,
                    variant.label()
                );
                Ok(artifacts)
            }
            Err(e) => {
                warn!(
                    "Failed to parse {} database ({}): {}",
                    variant.label(),
                    name,
                    e
                );
                let detail = format!(
                    "the {} database {name} could not be parsed ({e}); no message from it is \
                     in this case, and their absence here is not evidence they were absent \
                     from the device",
                    variant.label()
                );
                let metadata = json!({
                    // NOT `"WhatsApp"`. `conversation_summaries` selects
                    // ParsedRecords by `metadata.$.type` with no subtype filter
                    // and its thread key COALESCEs to the literal `'unknown'`,
                    // so a parse failure filed under the message type is
                    // counted as a message in a conversation the custodian
                    // never had. `INCOMPLETE_TYPE` is what every other marker
                    // in this parser uses.
                    "type": INCOMPLETE_TYPE,
                    "platform": format!("{:?}", variant),
                    "file_name": name,
                    "status": "ParseFailed",
                    "error": e.to_string(),
                    // The standard pair. Without it a msgstore that would not
                    // parse exports and reports as a database that held no
                    // messages — the same defect B3-022 fixed on the iMessage
                    // side and never swept across to here.
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                    // The keys the examiner-facing reader shows the sentence from.
                    "content_incomplete_detail": detail,
                    "inventory_incomplete_detail": detail,
                    "name": format!("{} Database (parse failed): {}", variant.label(), name),
                });
                let id_artifact =
                    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(artifact.id);
                Ok(vec![id_artifact])
            }
        }
    }
}
