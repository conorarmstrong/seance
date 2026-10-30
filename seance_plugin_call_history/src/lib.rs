#![forbid(unsafe_code)]
//! Call History Parser Module
//!
//! Parses mobile call-log databases (iOS `CallHistory.storedata` and Android
//! `contacts2.db` / `calllog.db`) extracting individual call records as forensic
//! artifacts.
//!
//! ## Supported Databases
//!
//! - iOS `CallHistory.storedata` — Core Data SQLite; table `ZCALLRECORD`.
//! - Android `calls` table — found in `contacts2.db` (legacy) or `calllog.db`.
//!
//! ## Schema
//!
//! - iOS `ZCALLRECORD`: `ZADDRESS` (phone/handle, may be a BLOB), `ZDATE`
//!   (Cocoa/Mac-absolute epoch seconds since 2001-01-01), `ZDURATION` (seconds),
//!   `ZORIGINATED` (1=outgoing,0=incoming), `ZANSWERED`, `ZCALLTYPE`.
//! - Android `calls`: `number`, `date` (Unix milliseconds), `duration`
//!   (seconds), `type` (1=incoming,2=outgoing,3=missed).
//!
//! ## Schema drift
//!
//! The Android stores' `PRAGMA user_version` is checked against the window
//! observed on real files — `calllog.db` and `contacts2.db` keep separate
//! counters, so each has its own (`AndroidStore::supported`). The Core Data
//! store has no numeric version, so no window is declared for it. Every column
//! on both walks is resolved through a field map; a store outside its window,
//! or one whose columns no candidate name matches, still parses and carries a
//! `ParserStaleWarning` record naming the version or the unresolved fields.
//!
//! ## Timestamps
//!
//! iOS `ZDATE` is Cocoa/Core Data epoch (seconds since 2001-01-01). Android
//! `calls.date` is Unix epoch milliseconds, though a store recovered from a
//! backup or written by a third-party dialler may hold seconds or microseconds
//! instead, so its unit is judged from the magnitude by the one shared band
//! table, [`seance_sqlite_util::unix_parts_from_magnitude`], rather than by a
//! rule local to this file. Both are surfaced as a Unix-seconds
//! integer (`timestamp`) plus an RFC3339 string (`timestamp_rfc3339`), matching
//! how the SMS/iMessage parsers store their `date`. Both sources also record a
//! sub-second part — `ZDATE` is REAL, `calls.date` is milliseconds — and it is
//! kept: `timestamp_ns` carries full Unix nanoseconds whenever the fraction is
//! non-zero, and the RFC3339 string shows it, because inside one second the
//! fraction is the only thing that orders two calls.

#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use seance_core::time::{cocoa_secs_to_unix_nanos, unix_ns};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::adopt::inline_marker::{user_version_marker, TableFields as Fields};
use seance_sqlite_util::chat::unix_parts_from_magnitude;
use seance_sqlite_util::spilled::table_exists;
use seance_sqlite_util::SupportedRange;
use serde_json::{json, Value};
use tracing::debug;
use uuid::Uuid;

/// Maximum number of call records to extract per database.
const MAX_CALL_ENTRIES: usize = 200_000;

/// Maximum on-disk database size we will spill and open.
const MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub struct CallHistoryParser;

/// Which Android provider wrote the `calls` table. The two keep separate
/// `PRAGMA user_version` counters, so each has its own validated window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AndroidStore {
    /// `calllog.db`, the CallLogProvider store (Android 4.2 onwards).
    CallLog,
    /// `contacts2.db`, where the ContactsProvider kept `calls` before that.
    Contacts2,
}

impl AndroidStore {
    fn classify(file_name: &str) -> Self {
        let lower = file_name.to_ascii_lowercase();
        if lower.ends_with("contacts2.db") {
            AndroidStore::Contacts2
        } else {
            AndroidStore::CallLog
        }
    }

    /// The parser identity a schema warning is filed under.
    fn app(self) -> &'static str {
        match self {
            AndroidStore::CallLog => "android-calllog",
            AndroidStore::Contacts2 => "android-contacts2-calls",
        }
    }

    /// The `PRAGMA user_version` window validated on real stores, and nothing
    /// wider. `calllog.db`: 5, seen once (Magnet 2022 CTF Pixel 3), so the
    /// window is that single version. `contacts2.db`: 1, seen once (Magnet
    /// 2019 Android CTF, the agent-written store); plaso's
    /// `test_data/contacts2.db` carries no version (`PRAGMA user_version` 0,
    /// SQLite's default), which is the absence of a version rather than an
    /// endpoint. A version outside the window still parses and carries a
    /// `ParserStaleWarning`.
    fn supported(self) -> SupportedRange {
        match self {
            AndroidStore::CallLog => SupportedRange::new(5, Some(5)),
            AndroidStore::Contacts2 => SupportedRange::new(1, Some(1)),
        }
    }

    /// The real store the window was read out of, written on every schema
    /// record as `validated_against`.
    fn evidence(self) -> &'static str {
        match self {
            AndroidStore::CallLog => {
                "Magnet 2022 CTF Pixel 3 calllog.db \
                 (user_version 5)"
            }
            AndroidStore::Contacts2 => {
                "Magnet 2019 Android CTF contacts2.db (the agent-written store) \
                 (user_version 1)"
            }
        }
    }
}

/// The parser identity the iOS walk files schema findings under.
///
/// No version window is declared for it: `CallHistory.storedata` is a Core Data
/// store, whose `PRAGMA user_version` was 0 on the one real file observed
/// (Magnet 2022 CTF iPhone 8) and whose model version lives as hashes in
/// `Z_METADATA.Z_PLIST`, not as a number a range can be drawn on. Drift there is
/// caught by the column map alone.
const IOS_APP: &str = "ios-callhistory";

/// The logical fields each walk reads, with the physical columns that carried
/// them in the real stores named above. `id` accepts `id` as well as `_id`
/// because the Magnet 2019 Android CTF `contacts2.db`, written by the
/// acquisition agent, keys its `calls` table that way.
const ANDROID_CALL_FIELDS: &[(&str, &[&str])] = &[
    ("id", &["_id", "id"]),
    ("number", &["number"]),
    ("date", &["date"]),
    ("duration", &["duration"]),
    ("type", &["type"]),
];
const IOS_CALL_FIELDS: &[(&str, &[&str])] = &[
    ("pk", &["Z_PK"]),
    ("address", &["ZADDRESS"]),
    ("date", &["ZDATE"]),
    ("duration", &["ZDURATION"]),
    ("originated", &["ZORIGINATED"]),
    ("answered", &["ZANSWERED"]),
    ("call_type", &["ZCALLTYPE"]),
];

/// Permissive filename pre-filter (only decides whether to open the file). The
/// authoritative check is the schema (`ZCALLRECORD` for iOS or the `calls`
/// table for Android), run after opening, which rejects any false positive.
/// Matching on suffix/substring means renamed or path-prefixed copies are still
/// parsed. `contacts2.db` is shared with the contacts parser: schema decides.
fn identify_call_history_db(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("callhistory.storedata")
        || n.contains("callhistory")
        || n.ends_with("contacts2.db")
        || n.ends_with("calllog.db")
        || n.contains("calllog")
}

/// RFC3339 string for a Unix `(seconds, nanos)` instant. None if out of range.
///
/// The nanos are rendered, not dropped: the string is what an examiner reads and
/// what a report quotes, so rounding it to the whole second would contradict the
/// `timestamp_ns` field on the same record.
fn to_rfc3339(secs: i64, nanos: u32) -> Option<String> {
    chrono::DateTime::from_timestamp(secs, nanos).map(|dt| dt.to_rfc3339())
}

/// Convert a raw Android telephony epoch value to Unix seconds plus the
/// sub-second nanoseconds, or `None` where the column recorded no instant.
///
/// This is [`unix_parts_from_magnitude`] and nothing else. It used to be a local
/// two-branch rule — below 10^11 seconds, at or above it milliseconds — which is
/// right for the unit Android itself writes and wrong for the third unit this
/// corpus contains: a 16-digit microsecond value was divided by a thousand and
/// dated the call to the year 55840. The shared normaliser judges microseconds,
/// milliseconds and seconds by one band table, and it is the same table the
/// seconds-only callers use, so a parser that keeps the fraction and a parser
/// that drops it cannot place the same stored value in different years.
///
/// The sub-second part is evidence rather than noise: two calls inside the same
/// second are ordered only by it, so it is carried into the nanos instead of
/// being divided away. A microsecond value now keeps all six of its fractional
/// digits, where the old rule turned them into a thousandfold-inflated seconds
/// count.
///
/// Returning `None` for a non-positive `date` restates what the Android caller
/// already did with an explicit `> 0` filter; it is not a change in behaviour
/// here, only a move of the rule to the one place that states it.
fn normalize_epoch_parts(raw: i64) -> Option<(i64, u32)> {
    unix_parts_from_magnitude(raw)
}

/// Interpret a SQLite value as a best-effort string. `ZADDRESS` may be stored as
/// TEXT or as a BLOB (raw phone-number bytes), so both must be handled.
fn value_to_string(v: ValueRef<'_>) -> Option<String> {
    match v {
        ValueRef::Null => None,
        ValueRef::Text(t) => {
            let s = String::from_utf8_lossy(t).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        ValueRef::Blob(b) => {
            let s = String::from_utf8_lossy(b);
            let s = s.trim_matches('\0').trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(r) => Some(r.to_string()),
    }
}

/// Push the shared metadata fields and build a call `ParsedRecord`.
///
/// `direction` is [`DIRECTION_UNKNOWN`] when the source columns did not record
/// it, and `duration_seconds` is `None` when the duration column was NULL: both
/// are written as an explicit unknown rather than a plausible-looking default,
/// because "missed call, 0 seconds" is an affirmative statement about the
/// evidence that nothing downstream could tell from an invented one.
#[allow(clippy::too_many_arguments)]
fn build_call_record(
    case_id: Uuid,
    parent_id: Uuid,
    platform: &str,
    rowid: i64,
    number: Option<String>,
    direction: &str,
    timestamp: Option<(i64, u32)>,
    duration_seconds: Option<i64>,
    extra: &[(&str, Value)],
) -> Artifact {
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("CallLog"));
    meta.insert("subtype".into(), json!("call"));
    meta.insert("platform".into(), json!(platform));
    meta.insert("rowid".into(), json!(rowid));
    meta.insert("direction".into(), json!(direction));
    // Null, not 0: a NULL duration column is "not recorded", and a 0 would read
    // as a call that connected for no time at all.
    meta.insert("duration_seconds".into(), json!(duration_seconds));

    let contact = number.clone().unwrap_or_else(|| "Unknown".to_string());
    meta.insert("number".into(), json!(number));
    meta.insert("contact".into(), json!(contact));

    if let Some((secs, nanos)) = timestamp {
        meta.insert("timestamp".into(), json!(secs));
        if let Some(r) = to_rfc3339(secs, nanos) {
            meta.insert("timestamp_rfc3339".into(), json!(r));
        }
        // Sub-second part, beside the whole seconds rather than instead of them.
        // `ZDATE` is a REAL column and `calls.date` is milliseconds: two calls
        // placed inside the same second are ordered only by the fraction, so a
        // record that published seconds alone lost the order they happened in.
        if let Some(ns) = unix_ns(secs, nanos) {
            meta.insert("timestamp_ns".into(), json!(ns));
        }
    }

    for (k, v) in extra {
        meta.insert((*k).to_string(), v.clone());
    }

    let duration_label = match duration_seconds {
        Some(d) => format!("{}s", d),
        None => "duration unknown".to_string(),
    };
    meta.insert(
        "name".into(),
        json!(format!(
            "{} call: {} ({})",
            direction, contact, duration_label
        )),
    );

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("call")
}

/// What one call-log table yielded.
///
/// `truncated` is the load-bearing field: `count` is what this tool extracted,
/// not what the device recorded. Both Android and iOS walks read newest-first,
/// so the rows a cap drops are the **oldest** calls — exactly the ones an
/// examiner reaches for when establishing a first contact between two parties.
/// Reporting the capped count as the call count would let a 500k-call log
/// present its most recent 200k as the complete history.
struct CallExtraction {
    artifacts: Vec<Artifact>,
    count: usize,
    truncated: bool,
    /// Rows the walk fetched and could not decode. Counted rather than merely
    /// logged: a `continue` alone makes them vanish, after which `call_count`
    /// reads as the exact number of calls on the device instead of a floor.
    dropped_rows: usize,
    /// Schema findings: a version outside the validated window, or a column
    /// the parser knows by a name the store no longer uses.
    markers: Vec<Artifact>,
}

/// The direction a call record carries when the source columns did not record
/// one. Never "missed" or "incoming": a fabricated direction is an affirmative
/// claim about who contacted whom that nothing downstream can detect.
const DIRECTION_UNKNOWN: &str = "unknown";

/// Parse iOS `CallHistory.storedata` (`ZCALLRECORD` table).
fn parse_ios_calls(conn: &Connection, case_id: Uuid, parent_id: Uuid) -> Result<CallExtraction> {
    let mut artifacts = Vec::new();
    let mut truncated = false;
    let mut dropped_rows = 0usize;

    let fields = Fields::resolve(conn, IOS_APP, "ZCALLRECORD", IOS_CALL_FIELDS)?;
    let select = format!(
        "SELECT {pk}, {address}, {date}, {duration}, {originated}, {answered}, {call_type}
         FROM ZCALLRECORD ORDER BY {date} DESC",
        pk = fields.col_or("pk", "rowid"),
        address = fields.col("address"),
        date = fields.col("date"),
        duration = fields.col("duration"),
        originated = fields.col("originated"),
        answered = fields.col("answered"),
        call_type = fields.col("call_type"),
    );
    let mut stmt = conn
        .prepare(&select)
        .context("Failed to prepare ZCALLRECORD query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,            // Z_PK
                value_to_string(row.get_ref(1)?), // ZADDRESS (may be BLOB)
                row.get::<_, Option<f64>>(2)?,    // ZDATE (cocoa seconds)
                row.get::<_, Option<f64>>(3)?,    // ZDURATION (seconds)
                row.get::<_, Option<i64>>(4)?,    // ZORIGINATED
                row.get::<_, Option<i64>>(5)?,    // ZANSWERED
                row.get::<_, Option<i64>>(6)?,    // ZCALLTYPE
            ))
        })
        .context("Failed to query ZCALLRECORD rows")?;

    for row in rows {
        if artifacts.len() >= MAX_CALL_ENTRIES {
            truncated = true;
            break;
        }
        let (pk, address, zdate, zduration, originated, answered, call_type) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skipping malformed ZCALLRECORD row: {}", e);
                dropped_rows += 1;
                continue;
            }
        };

        // `ZORIGINATED` is the only column that says who placed the call, and
        // `ZANSWERED` the only one that says whether an inbound call connected.
        // A NULL in either never recorded that fact, so it must not become
        // "missed" or "incoming" — direction IS the evidentiary content of a
        // call record, and an invented one is indistinguishable downstream from
        // one the device wrote.
        let direction = match originated {
            Some(1) => "outgoing",
            // Originated = 0 is definitively inbound. Whether it was answered
            // refines that to "missed"; with ZANSWERED NULL the refinement is
            // unknown, so the record stays at the fact that was recorded.
            Some(0) => match answered {
                Some(0) => "missed",
                _ => "incoming",
            },
            _ => DIRECTION_UNKNOWN,
        };

        // A Core Data `ZDATE` of 0 (or negative) is "unset", not 2001-01-01;
        // drop it so the record is honestly undated rather than fabricating an
        // epoch timestamp. Mirrors the iMessage/WhatsApp parsers.
        //
        // `ZDATE` is REAL and the fraction is real evidence — it is what orders
        // two calls placed inside the same second — so decode to (seconds,
        // nanos) rather than through the whole-seconds helper.
        let timestamp = zdate.and_then(cocoa_secs_to_unix_nanos);
        let duration_seconds = zduration.map(|d| d as i64);

        // NULL flags stay null: `answered: false` on a row that never recorded
        // the flag is a statement that the call was not picked up.
        let mut extra = vec![
            ("answered", json!(answered.map(|a| a != 0))),
            ("originated", json!(originated.map(|o| o != 0))),
            ("call_type", json!(call_type)),
        ];
        // Same statement as the Android walk makes, so one parser does not
        // describe an unreadable time two different ways: the raw value is the
        // `ZDATE` column exactly as stored, in Core Data's own 2001 epoch,
        // which is why it is not offered under a key that reads as an instant.
        if timestamp.is_none() {
            if let Some(raw) = zdate {
                extra.push(("timestamp_unusable", json!(true)));
                extra.push(("timestamp_raw", json!(raw)));
            }
        }

        artifacts.push(build_call_record(
            case_id,
            parent_id,
            "iOS",
            pk,
            address,
            direction,
            timestamp,
            duration_seconds,
            &extra,
        ));
    }

    let count = artifacts.len();
    let markers = fields
        .drift_marker(case_id, parent_id, count)
        .into_iter()
        .collect();
    Ok(CallExtraction {
        artifacts,
        count,
        truncated,
        dropped_rows,
        markers,
    })
}

/// Map an Android `calls.type` code to a direction string. `None` (a NULL
/// column) and any code the platform does not define both reach
/// [`DIRECTION_UNKNOWN`].
fn android_call_direction(call_type: Option<i64>) -> &'static str {
    match call_type {
        Some(1) => "incoming",
        Some(2) => "outgoing",
        Some(3) => "missed",
        Some(4) => "voicemail",
        Some(5) => "rejected",
        Some(6) => "blocked",
        _ => DIRECTION_UNKNOWN,
    }
}

/// Parse the Android `calls` table.
fn parse_android_calls(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    store: AndroidStore,
) -> Result<CallExtraction> {
    let mut artifacts = Vec::new();
    let mut truncated = false;
    let mut dropped_rows = 0usize;
    let mut markers = Vec::new();
    markers.extend(user_version_marker(
        conn,
        case_id,
        parent_id,
        store.app(),
        &store.supported(),
        store.evidence(),
    ));

    // `name` (cached contact name) is present on most Android versions but not
    // all; select only the columns every validated store carried.
    let fields = Fields::resolve(conn, store.app(), "calls", ANDROID_CALL_FIELDS)?;
    let select = format!(
        "SELECT {id}, {number}, {date}, {duration}, {kind} FROM calls ORDER BY {date} DESC",
        id = fields.col_or("id", "rowid"),
        number = fields.col("number"),
        date = fields.col("date"),
        duration = fields.col("duration"),
        kind = fields.col("type"),
    );
    let mut stmt = conn
        .prepare(&select)
        .context("Failed to prepare calls query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,            // _id
                value_to_string(row.get_ref(1)?), // number (may be BLOB on some ROMs)
                row.get::<_, Option<i64>>(2)?,    // date (millis)
                row.get::<_, Option<i64>>(3)?,    // duration (seconds)
                row.get::<_, Option<i64>>(4)?,    // type
            ))
        })
        .context("Failed to query calls rows")?;

    for row in rows {
        if artifacts.len() >= MAX_CALL_ENTRIES {
            truncated = true;
            break;
        }
        let (id, number, date, duration, call_type) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skipping malformed calls row: {}", e);
                dropped_rows += 1;
                continue;
            }
        };

        let direction = android_call_direction(call_type);
        // `date` of 0 (or negative) is unset, not 1970-01-01; the shared
        // normaliser drops it rather than storing a fabricated epoch timestamp.
        // The fraction it does record stays with it as nanos.
        let timestamp = date.and_then(normalize_epoch_parts);
        let duration_seconds = duration;

        // Null, not 0: `call_type: 0` is not a value Android writes, and
        // recording one puts a column value in the record that the device never
        // held.
        let mut extra = vec![("call_type", json!(call_type))];
        // The column held a value and no reading of it is an instant. That the
        // store wrote a literal 0 (or a negative) is an observation worth
        // keeping, so it is kept — under keys no consumer can mistake for a
        // time, matching the `_unusable`/`_raw` pair the utmp parser already
        // uses for the same situation. A NULL column leaves no mark, so "the
        // store held no time" stays distinguishable from "the store held one
        // that cannot be read".
        if timestamp.is_none() {
            if let Some(raw) = date {
                extra.push(("timestamp_unusable", json!(true)));
                extra.push(("timestamp_raw", json!(raw)));
            }
        }

        artifacts.push(build_call_record(
            case_id,
            parent_id,
            "Android",
            id,
            number,
            direction,
            timestamp,
            duration_seconds,
            &extra,
        ));
    }

    let count = artifacts.len();
    markers.extend(fields.drift_marker(case_id, parent_id, count));
    Ok(CallExtraction {
        artifacts,
        count,
        truncated,
        dropped_rows,
        markers,
    })
}

/// Parse a call-history database, dispatching on the detected schema, and append
/// a summary record.
fn parse_call_history(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Result<Vec<Artifact>> {
    let (extraction, platform) = if table_exists(conn, "ZCALLRECORD")? {
        (parse_ios_calls(conn, case_id, parent_id)?, "iOS")
    } else if table_exists(conn, "calls")? {
        let store = AndroidStore::classify(file_name);
        (
            parse_android_calls(conn, case_id, parent_id, store)?,
            "Android",
        )
    } else {
        // Neither schema present: not our database.
        return Ok(Vec::new());
    };
    let CallExtraction {
        mut artifacts,
        count,
        truncated,
        dropped_rows,
        markers,
    } = extraction;

    // Tallied over the call records alone, before the schema findings join
    // the list: the direction tally counts every record it is handed, and a
    // marker with no direction would be counted as a call whose direction the
    // device never recorded.
    let summary = build_call_summary(
        &artifacts,
        platform,
        file_name,
        count,
        truncated,
        dropped_rows,
    );
    // The schema findings sit between the records and the summary, so a reader
    // walking the list meets them before the totals they qualify.
    artifacts.extend(markers);
    artifacts.push(
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, summary)
            .with_parent(parent_id)
            .with_subtype("summary"),
    );

    Ok(artifacts)
}

/// Build the `CallLog` summary metadata for one parsed database.
///
/// Forensic meaning: `call_count` is the number of calls THIS TOOL extracted.
/// When `truncated` is set, the walk stopped at a safety cap — both platforms
/// read newest-first, so the calls that were dropped are the oldest ones. The
/// flag is what stops "200000 calls" from being read as "the phone made 200000
/// calls".
fn build_call_summary(
    artifacts: &[Artifact],
    platform: &str,
    file_name: &str,
    count: usize,
    truncated: bool,
    dropped_rows: usize,
) -> Value {
    let mut incoming = 0usize;
    let mut outgoing = 0usize;
    let mut missed = 0usize;
    let mut unknown = 0usize;
    let mut other = 0usize;
    for a in artifacts {
        // Every direction is counted in its own bucket. A catch-all that folded
        // "unknown" into `incoming_count` would republish, as a tally, exactly
        // the invented direction the per-record path refuses to write.
        match a.metadata["direction"]
            .as_str()
            .unwrap_or(DIRECTION_UNKNOWN)
        {
            "outgoing" => outgoing += 1,
            "missed" => missed += 1,
            "incoming" => incoming += 1,
            DIRECTION_UNKNOWN => unknown += 1,
            _ => other += 1,
        }
    }

    let mut summary = serde_json::Map::new();
    summary.insert("type".into(), json!("CallLog"));
    summary.insert("subtype".into(), json!("summary"));
    summary.insert("platform".into(), json!(platform));
    summary.insert("call_count".into(), json!(count));
    summary.insert("incoming_count".into(), json!(incoming));
    summary.insert("outgoing_count".into(), json!(outgoing));
    summary.insert("missed_count".into(), json!(missed));
    // Calls whose direction the device never recorded, and calls the platform
    // typed as voicemail/rejected/blocked. Both are reported rather than folded
    // into a direction they were not.
    summary.insert("unknown_direction_count".into(), json!(unknown));
    summary.insert("other_direction_count".into(), json!(other));
    summary.insert("file_name".into(), json!(file_name));
    if truncated {
        summary.insert("truncated".into(), json!(true));
        summary.insert("content_incomplete".into(), json!(true));
        summary.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::CapReached.as_str()),
        );
        summary.insert("max_entries".into(), json!(MAX_CALL_ENTRIES));
        summary.insert(
            "message".into(),
            json!("Call log walk stopped at the parser cap; the oldest calls were not extracted"),
        );
    }
    if dropped_rows > 0 {
        // Rows that were in the log and would not decode. Without this the count
        // above reads as the exact number of calls the device placed or
        // received, and an examiner could testify that a call never happened
        // when in fact its row could not be read.
        summary.insert("rows_dropped".into(), json!(dropped_rows));
        summary.insert("inventory_incomplete".into(), json!(true));
        summary.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
        summary.insert("content_incomplete".into(), json!(true));
        // A cap is the coarser statement; do not overwrite it.
        summary
            .entry("content_incomplete_reason")
            .or_insert_with(|| json!(IncompleteReason::UnresolvedStructure.as_str()));
    }
    summary.insert(
        "name".into(),
        json!(format!("Call History: {} calls ({})", count, platform)),
    );
    Value::Object(summary)
}

impl ForensicsModule for CallHistoryParser {
    fn id(&self) -> &str {
        "plugin.mobile.call_history"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
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
        if !identify_call_history_db(name) {
            return Ok(Vec::new());
        }
        seance_sqlite_util::spilled::process_spilled_db(
            artifact,
            name,
            &seance_sqlite_util::spilled::SpilledDbSpec {
                log_label: "CallHistoryParser",
                spill_tag: "call_history",
                record_type: "CallLog",
                display_name: "Call History",
                noun: "call-history",
                schema_tables: &["ZCALLRECORD", "calls"],
                max_db_bytes: MAX_DB_BYTES,
            },
            parse_call_history,
        )
    }
}

/// The magnitude contract: what this parser writes into `timestamp` must be a
/// whole Unix second an examiner could read as a date, whichever unit the
/// Android `calls.date` column happened to record — and the sub-second part it
/// carries must still be the fraction the store held, not a thousandfold copy
/// of it.
///
/// This lives beside the parser rather than in `tests.rs` because it is a
/// statement about the record this file emits, and it is the guard that stops a
/// future edit reintroducing a two-branch `raw < 10^11 ? raw : raw / 1000`
/// normaliser — which reads a 16-digit microsecond value as milliseconds and
/// dates the call to the year 55840.
#[cfg(test)]
mod magnitude_contract {
    use super::*;
    use seance_sqlite_util::chat::is_plausible_instant_secs;

    /// 2023-11-14T22:13:20.123456Z — the one instant every row below claims,
    /// written in each unit, each carrying as much of the fraction as its unit
    /// can express.
    const INSTANT_SECS: i64 = 1_700_000_000;
    const SAME_INSTANT_IN_EVERY_UNIT: [(&str, i64, u32); 3] = [
        ("seconds", 1_700_000_000, 0),
        ("milliseconds", 1_700_000_000_123, 123_000_000),
        ("microseconds", 1_700_000_000_123_456, 123_456_000),
    ];

    /// A `calls` table holding one row per supplied `date`, with everything
    /// else a call needs held constant.
    fn calls_db(dates: &[i64]) -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE calls (
                 _id INTEGER PRIMARY KEY, number TEXT, date INTEGER,
                 duration INTEGER, type INTEGER
             );",
        )
        .expect("create calls");
        for (i, date) in dates.iter().enumerate() {
            conn.execute(
                "INSERT INTO calls (_id, number, date, duration, type)
                 VALUES (?1, '+15550100', ?2, 42, 1)",
                rusqlite::params![i as i64 + 1, date],
            )
            .expect("insert call");
        }
        conn
    }

    fn parse(conn: &Connection) -> Vec<Artifact> {
        parse_android_calls(conn, Uuid::new_v4(), Uuid::new_v4(), AndroidStore::CallLog)
            .expect("parse")
            .artifacts
    }

    #[test]
    fn every_unit_of_one_instant_is_written_as_the_same_plausible_second() {
        let dates: Vec<i64> = SAME_INSTANT_IN_EVERY_UNIT
            .iter()
            .map(|(_, v, _)| *v)
            .collect();
        let artifacts = parse(&calls_db(&dates));
        assert_eq!(artifacts.len(), dates.len());

        for (unit, raw, nanos) in SAME_INSTANT_IN_EVERY_UNIT {
            let rowid = dates.iter().position(|d| *d == raw).expect("inserted") as i64 + 1;
            let call = artifacts
                .iter()
                .find(|a| a.metadata["rowid"].as_i64() == Some(rowid))
                .unwrap_or_else(|| panic!("no record for the {unit} row"));
            let secs = call.metadata["timestamp"]
                .as_i64()
                .unwrap_or_else(|| panic!("the {unit} row wrote a non-integer timestamp"));
            assert!(
                is_plausible_instant_secs(secs),
                "{unit} value {raw} was written as {secs}, which is not a date a \
                 call could carry"
            );
            assert_eq!(
                secs, INSTANT_SECS,
                "{unit} value {raw} names a different instant than the other units"
            );
            // The fraction is what orders two calls placed inside the same
            // second, so it has to survive the unit judgement rather than be
            // rescaled by it.
            assert_eq!(
                call.metadata["timestamp_ns"].as_i64(),
                unix_ns(INSTANT_SECS, nanos),
                "{unit} value {raw} lost or rescaled its sub-second part"
            );
        }
    }

    #[test]
    fn an_unset_date_leaves_the_call_undated_rather_than_at_the_epoch() {
        for unset in [0, -1] {
            let artifacts = parse(&calls_db(&[unset]));
            assert_eq!(artifacts.len(), 1);
            let call = &artifacts[0];
            // A call is still a call with no time on it; what it must never be
            // is a call dated 1970-01-01 (or 1969) because a column was unset.
            assert!(
                call.metadata.get("timestamp").is_none(),
                "an unset date of {unset} was written as {:?}",
                call.metadata.get("timestamp")
            );
            // No fabricated instant beside the omitted key, in either of the
            // two fields that would carry one.
            assert!(call.metadata.get("timestamp_rfc3339").is_none());
            assert!(call.metadata.get("timestamp_ns").is_none());
            // The observation survives under keys that cannot be read as a
            // time: the store did write something, and that is a fact about
            // the store.
            assert_eq!(call.metadata["timestamp_unusable"], true);
            assert_eq!(call.metadata["timestamp_raw"], unset);
        }
    }

    /// The same disclosure, on the other arm of the same parser.
    ///
    /// A fix applied to one seam and not its sibling is how this contract
    /// drifted in the first place, so the iOS walk is pinned beside the Android
    /// one rather than left to be inferred from it.
    #[test]
    fn an_unset_zdate_is_disclosed_the_same_way_the_android_walk_discloses_one() {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE ZCALLRECORD (
                 Z_PK INTEGER PRIMARY KEY, ZADDRESS TEXT, ZDATE REAL, ZDURATION REAL,
                 ZORIGINATED INTEGER, ZANSWERED INTEGER, ZCALLTYPE INTEGER
             );
             INSERT INTO ZCALLRECORD VALUES (1, '+15550100', 0.0, 42.0, 1, 1, 1);",
        )
        .expect("create ZCALLRECORD");
        let artifacts = parse_ios_calls(&conn, Uuid::new_v4(), Uuid::new_v4())
            .expect("parse")
            .artifacts;
        let call = &artifacts[0];
        // A `ZDATE` of 0 is an unset column, not midnight on 2001-01-01.
        assert!(call.metadata.get("timestamp").is_none());
        assert!(call.metadata.get("timestamp_rfc3339").is_none());
        assert!(call.metadata.get("timestamp_ns").is_none());
        assert_eq!(call.metadata["timestamp_unusable"], true);
        // The column exactly as stored, in Core Data's own 2001 epoch — which
        // is why it is not offered under a key that reads as an instant.
        assert_eq!(call.metadata["timestamp_raw"], 0.0);
    }

    /// The year named in this module's doc comment — and in the matching
    /// comments in `seance_plugin_android_sms` and `seance_plugin_signal`, which
    /// describe the same defect — is a measured consequence rather than a
    /// remembered one.
    ///
    /// A number written into prose rots silently, and this one had already
    /// drifted between copies of the sentence while they were being written.
    /// Measuring it here means an edit that changes the example value has to
    /// change the sentence with it.
    #[test]
    fn the_year_the_old_two_branch_rule_produced_is_the_year_those_comments_name() {
        use chrono::Datelike;
        let microseconds = 1_700_000_000_123_456i64;
        // What the old `abs < 10^11 ? raw : raw / 1000` made of it.
        let misread = microseconds / 1000;
        let dt = chrono::DateTime::from_timestamp(misread, 0).expect(
            "the misread value is still inside chrono's range, which is why it \
             rendered as a date instead of failing loudly",
        );
        assert_eq!(dt.year(), 55840);
        // And what the shared band table makes of the same value.
        assert_eq!(
            normalize_epoch_parts(microseconds),
            Some((INSTANT_SECS, 123_456_000))
        );
    }

    /// The plausible-instant window is documented in `seance_sqlite_util` as
    /// 1990-01-01Z to 2100-01-01Z, but that crate has no calendar to check the
    /// two constants against. This crate does, and it is one of the window's
    /// users, so it checks them here rather than leaving two bare integers
    /// standing on a comment.
    #[test]
    fn the_plausible_window_is_the_pair_of_dates_its_documentation_names() {
        use chrono::Datelike;
        let bound = |secs: i64| {
            let dt = chrono::DateTime::from_timestamp(secs, 0).expect("a real instant");
            (dt.year(), dt.month(), dt.day())
        };
        assert_eq!(
            bound(seance_sqlite_util::chat::PLAUSIBLE_INSTANT_MIN_SECS),
            (1990, 1, 1)
        );
        assert_eq!(
            bound(seance_sqlite_util::chat::PLAUSIBLE_INSTANT_MAX_SECS),
            (2100, 1, 1)
        );
        // And the window admits the instant every test above places, so a
        // passing contract test is not passing on a window that admits nothing.
        assert!(is_plausible_instant_secs(INSTANT_SECS));
    }
}
