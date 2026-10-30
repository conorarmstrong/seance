#![forbid(unsafe_code)]
//! Android Calendar provider parser module.
//!
//! [`AndroidCalendarParser`] inspects file artifacts and self-selects the Android
//! calendar store (`/data/data/com.android.providers.calendar/databases/calendar.db`,
//! or a bare `calendar.db`), emitting one `CalendarEvent`
//! [`ParsedRecord`](ArtifactType::ParsedRecord) per `Events` row plus one
//! `AndroidCalendarSummary` record per parsed file.
//!
//! # Record shape
//!
//! Events reuse the **same** `CalendarEvent` record shape as the iCalendar plugin
//! (`seance_plugin_ical`) so both share the frontend calendar viewer: `type` =
//! `"CalendarEvent"`, with `summary` (title), `description`, `location`, `dtstart`
//! / `dtend` (RFC 3339 strings), `all_day`, `recurrence`, and `organizer`. A
//! `source` = `"android_calendar"` field distinguishes the origin, and a `calendar`
//! field carries the joined `Calendars.calendar_displayName`.
//!
//! # Timestamps
//!
//! Android stores `dtstart` / `dtend` as Unix epoch **milliseconds**. They are
//! converted to RFC 3339 UTC strings (matching the ical plugin's `dtstart` / `dtend`
//! units and field names). Out-of-range values are omitted rather than fabricated.
//!
//! # Honesty & robustness
//!
//! Absent fields are omitted, never emitted as null. A `calendar.db` that lacks the
//! `Events` table is rejected (guards against unrelated files sharing the name).
//! Corrupt, truncated, or non-SQLite input never panics and never fails the
//! pipeline. A file that is not SQLite at all yields nothing; a SQLite store the
//! name identified that will not open, whose catalogue will not read, or whose
//! `Events` / `tree_entity` table will not list its columns, prepare or run
//! yields one `StoreUnreadable` marker naming SQLite's error — never an empty
//! result that reads as a device with no events or notes (HUNT-187).
//!
//! # Schema-drift defence
//!
//! Each store's `PRAGMA user_version` is compared against the range this parser
//! was validated against on a real database — `calendar.db` 600 and `keep.db` 95,
//! both from the android2022 (Pixel, Android 12) image, so each range is that
//! single version — and every column read is resolved through a candidate list
//! before a query is written. A store outside the range, one whose version is
//! not recorded, or one whose required column no candidate matched is still
//! parsed, and a `ParserStaleWarning` record is appended naming the version seen
//! or the fields unresolved. See [`schema_support`].

#[cfg(test)]
mod schema_golden_tests;
mod schema_support;

use anyhow::{Context, Result};

use rusqlite::Connection;
use schema_support::{
    assess_version, plan_columns, unresolved_fields_marker, user_version, ColumnPlan, SchemaSupport,
};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{
    probe_table, unreadable_store_marker, Presence, SchemaProbe, SupportedRange, TempDb,
};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use tracing::debug;
use uuid::Uuid;

/// The schema this parser was validated against: the one real `calendar.db`
/// this project holds (android2022, Pixel, Android 12; the provider stamps
/// `PRAGMA user_version`). One store, so a single-point range.
const CALENDAR_SUPPORT: SchemaSupport = SchemaSupport {
    app: "android-calendar",
    store: "calendar.db",
    record_type: "CalendarEvent",
    range: SupportedRange {
        min: 600,
        max: Some(600),
    },
    evidence: "android2022 data/data/com.android.providers.calendar/databases/calendar.db \
               (PRAGMA user_version 600)",
};

/// The `Events` columns this build reads; every one is present in the
/// validated store, so losing any is drift. The event's identity is read as
/// `rowid`, not `_id`: SQLite provides the rowid whether or not an `_id` column
/// is declared (and `_id INTEGER PRIMARY KEY` is its alias), whereas naming
/// `_id` fails the whole query on a table without one (HUNT-187).
const EVENT_FIELDS: &[(&str, &[&str])] = &[
    ("title", &["title"]),
    ("description", &["description"]),
    ("eventLocation", &["eventLocation"]),
    ("dtstart", &["dtstart"]),
    ("dtend", &["dtend"]),
    ("allDay", &["allDay"]),
    ("calendar_id", &["calendar_id"]),
    ("organizer", &["organizer"]),
    ("rrule", &["rrule"]),
];

const CALENDAR_NAME_FIELDS: &[(&str, &[&str])] = &[
    ("_id", &["_id"]),
    ("calendar_displayName", &["calendar_displayName"]),
];

/// The schema this parser was validated against: the one real `keep.db` this
/// project holds (android2022; the app stamps `PRAGMA user_version`).
const KEEP_SUPPORT: SchemaSupport = SchemaSupport {
    app: "google-keep",
    store: "keep.db",
    record_type: "AndroidNote",
    range: SupportedRange {
        min: 95,
        max: Some(95),
    },
    evidence: "android2022 data/data/com.google.android.keep/databases/keep.db \
               (PRAGMA user_version 95)",
};

/// `tree_entity` columns the validated store carries. The time columns have
/// carried other names in other versions, hence the candidate lists.
const KEEP_NOTE_FIELDS: &[(&str, &[&str])] = &[
    ("_id", &["_id"]),
    ("title", &["title"]),
    ("type", &["type"]),
    ("time_created", &["time_created", "timestamp"]),
    (
        "user_edited_timestamp",
        &["user_edited_timestamp", "time_last_updated"],
    ),
    ("is_trashed", &["is_trashed"]),
    ("is_archived", &["is_archived"]),
    ("color_name", &["color_name"]),
];

/// `tree_entity.text` is NOT a column of the validated store — a note's body
/// lives in `list_item` — so its absence is not drift.
const KEEP_NOTE_OPTIONAL_FIELDS: &[(&str, &[&str])] = &[("text", &["text"])];

const KEEP_ITEM_FIELDS: &[(&str, &[&str])] = &[
    ("text", &["text"]),
    ("list_parent_id", &["list_parent_id"]),
    ("order_in_parent", &["order_in_parent"]),
];

/// The SELECT expression for `logical`: its column, or `NULL` when no candidate
/// matched — which the plan's marker declares, so the substitution is never
/// silent.
fn sql_expr(plan: &ColumnPlan, logical: &str) -> String {
    plan.column(logical)
        .map(str::to_string)
        .unwrap_or_else(|| "NULL".to_string())
}

/// Cap on how many bytes of the database to read (64 MiB). A calendar store is
/// kilobytes to low megabytes in practice; the cap bounds a pathological input.
const MAX_CONTENT_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum number of events to extract per database.
const MAX_EVENT_ENTRIES: usize = 100_000;

/// Parses the Android Calendar provider database into `CalendarEvent` records.
pub struct AndroidCalendarParser;

impl AndroidCalendarParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AndroidCalendarParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for AndroidCalendarParser {
    fn id(&self) -> &str {
        "plugin.mobile.android_calendar"
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
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Self-select by filename / path. Anything else is not ours.
        if !is_android_calendar_db(name, path) {
            return Ok(Vec::new());
        }

        // Directories have no content.
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }

        // Metadata-only artifacts (no data source) cannot be parsed.
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        debug!("AndroidCalendarParser parsing {}", name);

        // Spill to a temp file (with its `-wal` sibling, where the newest rows
        // live) so rusqlite can open it. The spill removes itself on drop.
        let temp = match TempDb::spill(data.as_ref(), "android_calendar", MAX_CONTENT_BYTES) {
            Ok(t) => t,
            Err(e) => {
                // NOT "not ours": `is_android_calendar_db` already said it is.
                // The spill failed for an environmental reason — an unwritable
                // or full temp volume — and returning nothing here reads as a
                // device with no calendar entries. That is the same defect
                // found in the PST, Timeline and iOS readers (B8-038).
                debug!("AndroidCalendarParser could not stage {}: {}", name, e);
                return Ok(vec![unreadable_store_marker(
                    artifact.case_id,
                    artifact.id,
                    "AndroidCalendarEvent",
                    format!("the calendar database could not be staged for reading: {e}"),
                )]);
            }
        };

        // A file that is not SQLite at all stays silent; one that carries the
        // header and still will not open is the store unread (HUNT-187).
        let conn = match temp.open() {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to open {} as SQLite: {}", name, e);
                return Ok(store_would_not_open(
                    artifact.case_id,
                    artifact.id,
                    &temp,
                    "AndroidCalendarIncomplete",
                    name,
                    "calendar events",
                    &e,
                ));
            }
        };

        // Authoritative claim check: an unrelated `calendar.db` without an
        // `Events` table is not the Android calendar store — unless the spill
        // was short, in which case the table may simply be past the bytes we
        // hold, and "not the calendar store" would be the wrong conclusion.
        //
        // Tri-state, not `.unwrap_or(false)`: a damaged calendar store answers
        // the catalogue query with SQLITE_CORRUPT, and reading that as "no
        // Events table" reported an unreadable provider database as a device
        // whose owner kept no appointments (B8-039).
        match probe_table(&conn, "Events") {
            Presence::Present => {}
            Presence::Absent => {
                debug!("{} lacks Android calendar 'Events' table, skipping", name);
                let mut out = Vec::new();
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
                return Ok(out);
            }
            Presence::Undetermined(why) => {
                let mut out: Vec<Artifact> = undetermined_store(
                    artifact.case_id,
                    artifact.id,
                    &temp,
                    "AndroidCalendarIncomplete",
                    format!(
                        "`{name}` carries the SQLite header and its schema catalogue would not \
                         read, so whether this device held calendar events is undetermined \
                         rather than answered: {why}"
                    ),
                )
                .into_iter()
                .collect();
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
                return Ok(out);
            }
        }

        // A column list, prepare or query failure inside the parse is the store
        // identified and not examined — a marker, not a module error with no
        // artifact (HUNT-187).
        let mut out = match parse_calendar(&conn, artifact.case_id, artifact.id, name) {
            Ok(out) => out,
            Err(e) => {
                return Ok(store_would_not_query(
                    artifact.case_id,
                    artifact.id,
                    &temp,
                    "AndroidCalendarIncomplete",
                    name,
                    "Events",
                    "calendar events",
                    &e,
                ))
            }
        };
        // The row caps inside `parse_calendar` are stamped there; this carries
        // the OUTER shortfall — the database file itself not staged in full —
        // onto every event, so a partial calendar cannot read as a whole one
        // (B3-013).
        temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        Ok(out)
    }
}

/// Parses a Google Keep `keep.db` into `AndroidNote` records.
pub struct GoogleKeepParser;

impl GoogleKeepParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoogleKeepParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for GoogleKeepParser {
    fn id(&self) -> &str {
        "plugin.mobile.google_keep"
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
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_google_keep(name, path) {
            return Ok(Vec::new());
        }
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let temp = match TempDb::spill(data.as_ref(), "keep", MAX_CONTENT_BYTES) {
            Ok(t) => t,
            Err(e) => {
                // See the calendar parser above: the name already established
                // this is the Keep store, so silence would read as a device
                // with no notes.
                debug!("GoogleKeepParser could not stage {}: {}", name, e);
                return Ok(vec![unreadable_store_marker(
                    artifact.case_id,
                    artifact.id,
                    "GoogleKeepNote",
                    format!("the Keep database could not be staged for reading: {e}"),
                )]);
            }
        };

        // See the calendar parser: header-bearing and unopenable is declared.
        let conn = match temp.open() {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to open {} as SQLite: {}", name, e);
                return Ok(store_would_not_open(
                    artifact.case_id,
                    artifact.id,
                    &temp,
                    "AndroidNoteIncomplete",
                    name,
                    "Keep notes",
                    &e,
                ));
            }
        };
        // A keep.db without a `tree_entity` table is not the Keep store —
        // unless the spill was short, in which case the table may simply lie
        // past the bytes we hold. And a catalogue that will not READ is a third
        // answer: reporting it as "no tree_entity" filed a damaged notebook as
        // one the custodian never wrote in (B8-039).
        match probe_table(&conn, "tree_entity") {
            Presence::Present => {}
            Presence::Absent => {
                debug!("{} lacks Keep 'tree_entity' table, skipping", name);
                let mut out = Vec::new();
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
                return Ok(out);
            }
            Presence::Undetermined(why) => {
                let mut out: Vec<Artifact> = undetermined_store(
                    artifact.case_id,
                    artifact.id,
                    &temp,
                    "AndroidNoteIncomplete",
                    format!(
                        "`{name}` carries the SQLite header and its schema catalogue would not \
                         read, so whether this device held Keep notes is undetermined rather \
                         than answered: {why}"
                    ),
                )
                .into_iter()
                .collect();
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
                return Ok(out);
            }
        }
        let mut out = match parse_keep(&conn, artifact.case_id, artifact.id, name) {
            Ok(out) => out,
            Err(e) => {
                return Ok(store_would_not_query(
                    artifact.case_id,
                    artifact.id,
                    &temp,
                    "AndroidNoteIncomplete",
                    name,
                    "tree_entity",
                    "Keep notes",
                    &e,
                ))
            }
        };
        // The note cap inside `parse_keep` is stamped there; this carries the
        // OUTER shortfall — the database file itself not staged in full — onto
        // every note, so a partial notebook cannot read as a whole one
        // (B3-013).
        temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
        Ok(out)
    }
}

/// Decide whether this artifact is a Google Keep database.
fn is_google_keep(name: &str, path: &str) -> bool {
    name.eq_ignore_ascii_case("keep.db") || path.contains("com.google.android.keep")
}

/// A row read defensively from Keep's `tree_entity` (columns vary by version).
struct KeepRow {
    id: Option<i64>,
    title: Option<String>,
    text: Option<String>,
    note_type: Option<i64>,
    created: Option<i64>,
    edited: Option<i64>,
    trashed: Option<i64>,
    archived: Option<i64>,
    color: Option<String>,
}

/// Normalize a Keep timestamp (µs, ms, or s since epoch — version-dependent) to
/// Unix **seconds**. `None` for the 0/negative unset sentinel.
///
/// This is a **magnitude-based unit normaliser**, not an epoch conversion: every
/// branch is already relative to 1970, so it does not belong in
/// `seance_core::time` (which converts *foreign epochs* — FILETIME 1601, WebKit
/// 1601 µs, Cocoa 2001 — to Unix). Reach for `seance_core::time` if a future
/// Android store turns out to use one of those bases.
fn keep_time_to_unix_secs(v: i64) -> Option<i64> {
    if v <= 0 {
        return None;
    }
    let secs = if v > 1_000_000_000_000_000 {
        v / 1_000_000 // microseconds
    } else if v > 1_000_000_000_000 {
        v / 1000 // milliseconds
    } else {
        v // seconds
    };
    Some(secs)
}

/// Convert a Keep timestamp (µs, ms, or s since epoch — version-dependent) to
/// an RFC-3339 UTC string.
fn keep_time_to_rfc3339(v: i64) -> Option<String> {
    keep_time_to_unix_secs(v)
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Assemble the text of a list note's checklist items, in order.
///
/// Returns the items and how many rows would not decode. The count is not
/// optional: a checklist line is the content of the note, and one dropped
/// silently leaves a note body that reads as complete while missing a line the
/// custodian wrote (B4-033).
fn collect_list_items(
    probe: &mut SchemaProbe,
    conn: &Connection,
    items: Option<&ColumnPlan>,
    note_id: i64,
) -> (Vec<String>, usize) {
    // No `list_item` table, or one whose columns this parser reads did not
    // resolve (declared by the caller's marker): nothing to walk.
    let Some(plan) = items.filter(|plan| plan.missing_required().is_empty()) else {
        return (Vec::new(), 0);
    };
    // `list_item` IS listed, so a query that will not run against it is a
    // damaged store — never "this note had no checklist". Recorded, because
    // returning an empty item list silently drops lines the custodian wrote.
    let sql = format!(
        "SELECT {} FROM list_item WHERE {} = ?1 ORDER BY {}",
        sql_expr(plan, "text"),
        sql_expr(plan, "list_parent_id"),
        sql_expr(plan, "order_in_parent"),
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            probe.record_failure(format!("the `list_item` query would not prepare: {e}"));
            return (Vec::new(), 0);
        }
    };
    let iter = match stmt.query_map([note_id], |row| row.get::<_, Option<String>>(0)) {
        Ok(i) => i,
        Err(e) => {
            probe.record_failure(format!("the `list_item` walk would not run: {e}"));
            return (Vec::new(), 0);
        }
    };
    let mut items = Vec::new();
    let mut dropped = 0usize;
    for row in iter {
        match row {
            // A NULL item is an empty line, not a loss.
            Ok(text) => {
                if let Some(t) = text.filter(|s| !s.is_empty()) {
                    items.push(t);
                }
            }
            Err(_) => dropped += 1,
        }
    }
    (items, dropped)
}

/// Parse Keep notes from `tree_entity`, reading columns defensively by name.
fn parse_keep(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    name: &str,
) -> Result<Vec<Artifact>> {
    let mut note_rows_dropped = 0usize;
    let mut item_rows_dropped = 0usize;
    // Schema questions this parse could not answer, declared at the end rather
    // than spent as "the checklist table is not there" (B8-039).
    let mut probe = SchemaProbe::new();
    // The column sets are read before either query is written, so a renamed
    // column is declared by name rather than read as NULL in silence.
    let note_plan = plan_columns(
        conn,
        "tree_entity",
        KEEP_NOTE_FIELDS,
        KEEP_NOTE_OPTIONAL_FIELDS,
    )
    .map_err(|why| anyhow::anyhow!("Failed to read the tree_entity columns: {why}"))?;
    let item_plan = if probe.has_table(conn, "list_item") {
        Some(
            plan_columns(conn, "list_item", KEEP_ITEM_FIELDS, &[])
                .map_err(|why| anyhow::anyhow!("Failed to read the list_item columns: {why}"))?,
        )
    } else {
        None
    };
    // Fetch one row past the cap so "exactly at the cap" can be told apart from
    // "there was more" — a LIMIT that silently drops the oldest notes must never
    // present the remainder as the whole notebook (B2-050).
    let mut notes: Vec<KeepRow> = {
        let mut stmt = conn
            .prepare("SELECT * FROM tree_entity LIMIT ?1")
            .context("Failed to prepare Keep tree_entity query")?;
        let iter = stmt
            .query_map([MAX_EVENT_ENTRIES as i64 + 1], |row| {
                let gs = |logical: &str| {
                    note_plan
                        .column(logical)
                        .and_then(|c| row.get::<_, Option<String>>(c).ok().flatten())
                };
                let gi = |logical: &str| {
                    note_plan
                        .column(logical)
                        .and_then(|c| row.get::<_, Option<i64>>(c).ok().flatten())
                };
                Ok(KeepRow {
                    id: gi("_id"),
                    title: gs("title"),
                    text: gs("text"),
                    note_type: gi("type"),
                    created: gi("time_created"),
                    edited: gi("user_edited_timestamp"),
                    trashed: gi("is_trashed"),
                    archived: gi("is_archived"),
                    color: gs("color_name"),
                })
            })
            .context("Failed to query Keep tree_entity")?;
        let mut rows = Vec::new();
        for row in iter {
            match row {
                Ok(r) => rows.push(r),
                // A note that existed and would not decode is absent from the
                // notebook listing; counting it is what stops that listing
                // reading as exact (B4-014).
                Err(_) => note_rows_dropped += 1,
            }
        }
        rows
    };
    let truncated = notes.len() > MAX_EVENT_ENTRIES;
    notes.truncate(MAX_EVENT_ENTRIES);

    let mut artifacts = Vec::new();
    for note in notes {
        let title = note.title.filter(|s| !s.is_empty());
        let mut text = note.text.filter(|s| !s.is_empty());
        let mut this_note_items_dropped = 0usize;
        if let Some(id) = note.id {
            let (items, dropped) = collect_list_items(&mut probe, conn, item_plan.as_ref(), id);
            this_note_items_dropped = dropped;
            item_rows_dropped += dropped;
            if !items.is_empty() {
                let joined = items.join("\n");
                text = Some(match text {
                    Some(t) => format!("{t}\n{joined}"),
                    None => joined,
                });
            }
        }
        if title.is_none() && text.is_none() {
            continue; // empty shell (folder/label placeholder)
        }

        let mut md = Map::new();
        md.insert("type".into(), json!("AndroidNote"));
        md.insert("subtype".into(), json!("android_note"));
        md.insert("source".into(), json!("google_keep"));
        if let Some(t) = &title {
            md.insert("title".into(), json!(t));
        }
        if let Some(t) = &text {
            md.insert("text".into(), json!(t));
        }
        if note.note_type == Some(1) {
            md.insert("note_type".into(), json!("list"));
        }
        if let Some(c) = note.color {
            md.insert("color".into(), json!(c));
        }
        if let Some(c) = note.created {
            // Store `created` as normalized Unix seconds, not the raw
            // version-dependent (µs/ms/s) integer, so sorting/filtering and the
            // timeline treat it consistently as seconds.
            if let Some(secs) = keep_time_to_unix_secs(c) {
                md.insert("created".into(), json!(secs));
            }
            if let Some(r) = keep_time_to_rfc3339(c) {
                md.insert("created_rfc3339".into(), json!(r));
            }
        }
        if let Some(e) = note.edited {
            if let Some(r) = keep_time_to_rfc3339(e) {
                md.insert("edited_rfc3339".into(), json!(r));
            }
        }
        if let Some(v) = note.trashed {
            md.insert("is_trashed".into(), json!(v != 0));
        }
        if let Some(v) = note.archived {
            md.insert("is_archived".into(), json!(v != 0));
        }
        let display = title
            .clone()
            .or_else(|| {
                text.as_ref()
                    .map(|t| t.lines().next().unwrap_or("").to_string())
            })
            .unwrap_or_default();
        md.insert(
            "name".into(),
            json!(format!(
                "Note: {}",
                display.chars().take(60).collect::<String>()
            )),
        );

        if this_note_items_dropped > 0 {
            // The note's own body is short. The standard pair goes on the note,
            // not only on a summary somewhere else, because it is this record an
            // examiner reads (B4-033).
            md.insert("list_items_dropped".into(), json!(this_note_items_dropped));
            md.insert("content_incomplete".into(), json!(true));
            md.insert(
                "content_incomplete_reason".into(),
                json!(IncompleteReason::UnresolvedStructure.as_str()),
            );
        }

        artifacts.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(md))
                .with_parent(parent_id)
                .with_subtype("android_note"),
        );
    }
    if note_rows_dropped > 0 || item_rows_dropped > 0 {
        artifacts.push(rows_dropped_marker(
            case_id,
            parent_id,
            "AndroidNoteParseStatus",
            "google_keep",
            name,
            note_rows_dropped,
            item_rows_dropped,
            artifacts.len(),
            "Google Keep rows that could not be decoded are absent from the notes recovered",
        ));
    }
    if truncated {
        artifacts.push(cap_marker(
            case_id,
            parent_id,
            "AndroidNoteParseStatus",
            "android_note_incomplete",
            "google_keep",
            name,
            artifacts.len(),
            MAX_EVENT_ENTRIES,
            "Google Keep notes beyond the parser cap were not extracted",
        ));
    }
    // Counted before the marker joins the list, and over note records only, so
    // the marker never counts itself or another marker.
    let notes_recovered = artifacts
        .iter()
        .filter(|a| a.metadata["type"] == json!("AndroidNote"))
        .count();
    artifacts.extend(probe.marker(
        case_id,
        parent_id,
        "AndroidNoteIncomplete",
        "tree_entity",
        notes_recovered,
    ));
    for (table, plan) in [
        ("tree_entity", Some(&note_plan)),
        ("list_item", item_plan.as_ref()),
    ] {
        if let Some(plan) = plan.filter(|p| !p.missing_required().is_empty()) {
            artifacts.push(unresolved_fields_marker(
                &KEEP_SUPPORT,
                table,
                plan,
                notes_recovered,
                case_id,
                parent_id,
            ));
        }
    }
    artifacts.extend(assess_version(
        &KEEP_SUPPORT,
        &user_version(conn),
        case_id,
        parent_id,
    ));
    debug!("Parsed {} Keep notes from {}", artifacts.len(), name);
    Ok(artifacts)
}

/// A record stating that rows existed and could not be decoded.
///
/// Forensic meaning: a cap says "we stopped early"; this says "we read past
/// them and could not use them". Both leave records out of the listing, and
/// only the cap used to say so. Without this, an event or a note that was on
/// the device is absent from an inventory that still reads as exact, and "the
/// custodian had no such appointment" rests on a row that would not decode
/// (B4-014, B4-033).
#[allow(clippy::too_many_arguments)]
fn rows_dropped_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    source: &str,
    file_name: &str,
    primary_dropped: usize,
    secondary_dropped: usize,
    extracted: usize,
    message: &str,
) -> Artifact {
    let mut md = Map::new();
    md.insert("type".into(), json!(record_type));
    md.insert("subtype".into(), json!("parse_incomplete"));
    md.insert("status".into(), json!("RowsUndecodable"));
    md.insert("source".into(), json!(source));
    md.insert("file_name".into(), json!(file_name));
    md.insert("content_incomplete".into(), json!(true));
    md.insert(
        "content_incomplete_reason".into(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    md.insert("inventory_incomplete".into(), json!(true));
    md.insert(
        "inventory_incomplete_reason".into(),
        json!(IncompleteReason::UnresolvedStructure.as_str()),
    );
    md.insert("rows_dropped".into(), json!(primary_dropped));
    md.insert("secondary_rows_dropped".into(), json!(secondary_dropped));
    md.insert("extracted_count".into(), json!(extracted));
    md.insert("message".into(), json!(message));
    md.insert(
        "name".into(),
        json!(format!(
            "{source}: {primary_dropped} row(s) could not be decoded and are absent from the \
             {extracted} record(s) recovered"
        )),
    );
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(md))
        .with_parent(parent_id)
        .with_subtype("parse_incomplete")
}

/// A record stating that a safety cap stopped an extraction short.
///
/// Forensic meaning: the records that *are* in the case are a prefix, not the
/// whole store. Without this marker a 250k-event calendar or a 150k-note
/// notebook presents its first 100k as the complete set, and the absence of an
/// entry reads as proof it never existed.
#[allow(clippy::too_many_arguments)]
fn cap_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    subtype: &str,
    source: &str,
    file_name: &str,
    extracted: usize,
    cap: usize,
    message: &str,
) -> Artifact {
    let mut md = Map::new();
    md.insert("type".into(), json!(record_type));
    md.insert("subtype".into(), json!(subtype));
    md.insert("source".into(), json!(source));
    md.insert("file_name".into(), json!(file_name));
    md.insert("truncated".into(), json!(true));
    md.insert("content_incomplete".into(), json!(true));
    md.insert(
        "content_incomplete_reason".into(),
        json!(IncompleteReason::CapReached.as_str()),
    );
    md.insert("extracted_count".into(), json!(extracted));
    md.insert("max_entries".into(), json!(cap));
    md.insert("message".into(), json!(message));
    md.insert(
        "name".into(),
        json!(format!("{source}: extraction stopped at {cap} entries")),
    );
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(md))
        .with_parent(parent_id)
}

/// Decide whether this artifact is the Android calendar provider store.
fn is_android_calendar_db(name: &str, path: &str) -> bool {
    name.eq_ignore_ascii_case("calendar.db") || path.contains("com.android.providers.calendar")
}

/// True if the staged copy begins with the SQLite file magic.
///
/// Separates "this file named `calendar.db` is not a database at all" — which
/// stays silent, as it always has — from "this IS a database and its catalogue
/// would not read", which must be declared. Without the check, any unrelated
/// file matching the filename gate could be reported as a provider store this
/// tool failed to examine.
fn staged_looks_like_sqlite(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && seance_core::io::is_sqlite_header(&head)
}

/// The record that says a store carried the SQLite header and could not be
/// examined, or `None` when the staged bytes are not a database at all.
///
/// What an examiner learns: this device HELD a provider database and this tool
/// did not read it, so the absence of events or notes in the report is the
/// tool's silence rather than the device's. `record_type` names the records it
/// qualifies (`"AndroidCalendarIncomplete"`), never a type the parse's own
/// records carry, because `seance_db` groups by `metadata.$.type`.
fn undetermined_store(
    case_id: Uuid,
    parent_id: Uuid,
    temp: &TempDb,
    record_type: &str,
    detail: String,
) -> Option<Artifact> {
    if !staged_looks_like_sqlite(temp.path()) {
        return None;
    }
    Some(unreadable_store_marker(
        case_id,
        parent_id,
        record_type,
        detail,
    ))
}

/// What a store the name identified, and SQLite would not open, answers.
///
/// The filename gate had already said this is the provider store, so an empty
/// list would read as a device with no events or notes (HUNT-187). A staged file
/// that carries the SQLite header gets the unreadable marker naming SQLite's
/// error; one that does not is not a database at all and keeps the old silence,
/// because the gate is permissive and claiming an unread store for every file
/// called `calendar.db` would manufacture the opposite error. The outer spill
/// shortfall is stamped either way.
fn store_would_not_open(
    case_id: Uuid,
    parent_id: Uuid,
    temp: &TempDb,
    record_type: &str,
    name: &str,
    what: &str,
    err: &dyn std::fmt::Display,
) -> Vec<Artifact> {
    let mut out: Vec<Artifact> = undetermined_store(
        case_id,
        parent_id,
        temp,
        record_type,
        format!(
            "`{name}` carries the SQLite header and SQLite would not open it, so whether this \
             device held {what} is undetermined rather than answered: {err}"
        ),
    )
    .into_iter()
    .collect();
    temp.stamp_incompleteness(case_id, parent_id, name, &mut out);
    out
}

/// What a store whose catalogue read, and whose primary table then could not be
/// queried, answers: one unreadable marker naming the table and SQLite's error,
/// never `ModuleError::ParsingError` (an error row and no artifact) and never an
/// empty list (HUNT-187, the `B8-038`/`B8-039` contract).
#[allow(clippy::too_many_arguments)]
fn store_would_not_query(
    case_id: Uuid,
    parent_id: Uuid,
    temp: &TempDb,
    record_type: &str,
    name: &str,
    table: &str,
    what: &str,
    err: &anyhow::Error,
) -> Vec<Artifact> {
    let mut out = vec![unreadable_store_marker(
        case_id,
        parent_id,
        record_type,
        format!(
            "`{name}` holds the `{table}` table and it could not be queried, so whether this \
             device held {what} is undetermined rather than answered: {err:#}"
        ),
    )];
    temp.stamp_incompleteness(case_id, parent_id, name, &mut out);
    out
}

/// Build a `calendar_id -> calendar_displayName` map, and how many rows would
/// not decode. Empty when `Calendars` is absent or the column is missing.
///
/// The `Calendars` probe goes through [`SchemaProbe`]: a probe that could not be
/// answered leaves every event attributed to no calendar at all, which is a
/// change to what each record says, and it must not be spent as "this device had
/// one unnamed calendar" (B8-039).
fn build_calendar_names(
    probe: &mut SchemaProbe,
    conn: &Connection,
    names: Option<&ColumnPlan>,
) -> (HashMap<i64, String>, usize) {
    let mut map = HashMap::new();
    let mut dropped = 0usize;
    // No `Calendars` table, or one whose columns did not resolve (declared by
    // the caller's marker): nothing to join.
    let Some(plan) = names.filter(|plan| plan.missing_required().is_empty()) else {
        return (map, dropped);
    };
    // `Calendars` IS listed, so a query that will not run against it is a
    // damaged store, not a device with no named calendars. Recorded, because an
    // empty map re-attributes every event to no calendar at all.
    let sql = format!(
        "SELECT {}, {} FROM Calendars",
        sql_expr(plan, "_id"),
        sql_expr(plan, "calendar_displayName"),
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            probe.record_failure(format!("the `Calendars` query would not prepare: {e}"));
            return (map, dropped);
        }
    };
    let rows = match stmt.query_map([], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
    }) {
        Ok(r) => r,
        Err(e) => {
            probe.record_failure(format!("the `Calendars` walk would not run: {e}"));
            return (map, dropped);
        }
    };
    for row in rows {
        match row {
            Ok((id, disp)) => {
                if let Some(d) = disp.filter(|s| !s.is_empty()) {
                    map.insert(id, d);
                }
            }
            // A dropped calendar name re-attributes every event on that
            // calendar to no calendar at all; that is a change to what
            // the record says, so it is counted (B4-014).
            Err(_) => dropped += 1,
        }
    }
    (map, dropped)
}

/// RFC 3339 UTC string for a Unix epoch-milliseconds value, matching the ical
/// plugin's `dtstart` / `dtend` string form (`YYYY-MM-DDTHH:MM:SSZ`). `None` if out
/// of range, and `None` for 0: the provider's unset value, which converted would
/// be `1970-01-01T00:00:00Z`, a date no one entered (HUNT-187).
fn ms_to_rfc3339(ms: i64) -> Option<String> {
    if ms == 0 {
        return None;
    }
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Parse the `Events` table plus a trailing summary record.
fn parse_calendar(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Result<Vec<Artifact>> {
    // Schema questions this parse could not answer, declared at the end rather
    // than spent as "there were no named calendars" (B8-039).
    let mut probe = SchemaProbe::new();
    // The column sets are read before the queries are written: a `SELECT`
    // naming a column this store renamed fails whole, and a calendar would
    // then read as unreadable when only a column moved. A moved column is read
    // as NULL and declared by name.
    let event_plan = plan_columns(conn, "Events", EVENT_FIELDS, &[])
        .map_err(|why| anyhow::anyhow!("Failed to read the Events columns: {why}"))?;
    let name_plan = if probe.has_table(conn, "Calendars") {
        Some(
            plan_columns(conn, "Calendars", CALENDAR_NAME_FIELDS, &[])
                .map_err(|why| anyhow::anyhow!("Failed to read the Calendars columns: {why}"))?,
        )
    } else {
        None
    };
    let (cal_names, calendar_names_dropped) =
        build_calendar_names(&mut probe, conn, name_plan.as_ref());
    let mut event_rows_dropped = 0usize;

    let sql = format!(
        "SELECT rowid, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM Events ORDER BY {}",
        sql_expr(&event_plan, "title"),
        sql_expr(&event_plan, "description"),
        sql_expr(&event_plan, "eventLocation"),
        sql_expr(&event_plan, "dtstart"),
        sql_expr(&event_plan, "dtend"),
        sql_expr(&event_plan, "allDay"),
        sql_expr(&event_plan, "calendar_id"),
        sql_expr(&event_plan, "organizer"),
        sql_expr(&event_plan, "rrule"),
        sql_expr(&event_plan, "dtstart"),
    );
    let mut stmt = conn.prepare(&sql).context("prepare Events query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,            // rowid (`_id` where declared)
                row.get::<_, Option<String>>(1)?, // title
                row.get::<_, Option<String>>(2)?, // description
                row.get::<_, Option<String>>(3)?, // eventLocation
                row.get::<_, Option<i64>>(4)?,    // dtstart (epoch ms)
                row.get::<_, Option<i64>>(5)?,    // dtend (epoch ms)
                row.get::<_, Option<i64>>(6)?,    // allDay
                row.get::<_, Option<i64>>(7)?,    // calendar_id
                row.get::<_, Option<String>>(8)?, // organizer
                row.get::<_, Option<String>>(9)?, // rrule
            ))
        })
        .context("query Events rows")?;

    let mut artifacts = Vec::new();
    let mut event_count = 0usize;
    let mut truncated = false;

    for row in rows {
        if artifacts.len() >= MAX_EVENT_ENTRIES {
            truncated = true;
            break;
        }
        let (
            id,
            title,
            description,
            location,
            dtstart,
            dtend,
            all_day,
            calendar_id,
            organizer,
            rrule,
        ) = match row {
            Ok(r) => r,
            Err(e) => {
                debug!("Skipping malformed Events row: {}", e);
                event_rows_dropped += 1;
                continue;
            }
        };

        let mut m: Map<String, Value> = Map::new();
        // Shape mirrors seance_plugin_ical's CalendarEvent so both reuse the viewer.
        m.insert("type".into(), json!("CalendarEvent"));
        m.insert("source".into(), json!("android_calendar"));
        m.insert("rowid".into(), json!(id));

        let title = title.filter(|s| !s.is_empty());
        if let Some(t) = &title {
            m.insert("summary".into(), json!(t));
        }
        if let Some(d) = description.filter(|s| !s.is_empty()) {
            m.insert("description".into(), json!(d));
        }
        if let Some(loc) = location.filter(|s| !s.is_empty()) {
            m.insert("location".into(), json!(loc));
        }
        if let Some(rfc) = dtstart.and_then(ms_to_rfc3339) {
            m.insert("dtstart".into(), json!(rfc));
        }
        if let Some(rfc) = dtend.and_then(ms_to_rfc3339) {
            m.insert("dtend".into(), json!(rfc));
        }
        m.insert("all_day".into(), json!(all_day.unwrap_or(0) != 0));
        if let Some(rr) = rrule.filter(|s| !s.is_empty()) {
            m.insert("recurrence".into(), json!(rr));
        }
        if let Some(org) = organizer.filter(|s| !s.is_empty()) {
            m.insert("organizer".into(), json!(org));
        }
        if let Some(cal) = calendar_id.and_then(|cid| cal_names.get(&cid)) {
            m.insert("calendar".into(), json!(cal));
        }
        m.insert(
            "name".into(),
            json!(title.unwrap_or_else(|| "(no title)".to_string())),
        );

        artifacts.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
                .with_parent(parent_id),
        );
        event_count += 1;
    }

    // Trailing summary record.
    let mut summary: Map<String, Value> = Map::new();
    summary.insert("type".into(), json!("AndroidCalendarSummary"));
    summary.insert("subtype".into(), json!("android_calendar_summary"));
    summary.insert("event_count".into(), json!(event_count));
    summary.insert("source".into(), json!("android_calendar"));
    // `event_count` is what was extracted, not what the calendar holds. Say so
    // when the cap stopped the walk (B2-081).
    if truncated {
        summary.insert("truncated".into(), json!(true));
        summary.insert("content_incomplete".into(), json!(true));
        summary.insert(
            "content_incomplete_reason".into(),
            json!(IncompleteReason::CapReached.as_str()),
        );
        summary.insert("max_entries".into(), json!(MAX_EVENT_ENTRIES));
        summary.insert(
            "message".into(),
            json!("Calendar events beyond the parser cap were not extracted"),
        );
    }
    // Rows that would not decode are declared alongside the cap: both leave
    // events out of the listing (B4-014).
    summary.insert("event_rows_dropped".into(), json!(event_rows_dropped));
    summary.insert(
        "calendar_names_dropped".into(),
        json!(calendar_names_dropped),
    );
    if event_rows_dropped > 0 || calendar_names_dropped > 0 {
        summary.insert("content_incomplete".into(), json!(true));
        summary.insert(
            "content_incomplete_reason".into(),
            json!(if truncated {
                IncompleteReason::CapReached.as_str()
            } else {
                IncompleteReason::UnresolvedStructure.as_str()
            }),
        );
        summary.insert("inventory_incomplete".into(), json!(true));
        summary.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
    }
    summary.insert(
        "name".into(),
        json!(format!(
            "Android calendar: {} events ({})",
            event_count, file_name
        )),
    );
    artifacts.push(
        Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            Value::Object(summary),
        )
        .with_parent(parent_id),
    );

    artifacts.extend(probe.marker(
        case_id,
        parent_id,
        "AndroidCalendarIncomplete",
        "Events",
        event_count,
    ));
    for (table, plan) in [
        ("Events", Some(&event_plan)),
        ("Calendars", name_plan.as_ref()),
    ] {
        if let Some(plan) = plan.filter(|p| !p.missing_required().is_empty()) {
            artifacts.push(unresolved_fields_marker(
                &CALENDAR_SUPPORT,
                table,
                plan,
                event_count,
                case_id,
                parent_id,
            ));
        }
    }
    artifacts.extend(assess_version(
        &CALENDAR_SUPPORT,
        &user_version(conn),
        case_id,
        parent_id,
    ));

    Ok(artifacts)
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
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use std::fs;
    use std::sync::Arc;

    /// Serialise a SQLite DB built from `sql` to raw bytes.
    fn build_db(sql: &str) -> Vec<u8> {
        let temp_path = std::env::temp_dir().join(format!("seance_cal_test_{}.db", Uuid::new_v4()));
        {
            let conn = Connection::open(&temp_path).unwrap();
            conn.execute_batch(sql).unwrap();
        }
        let data = fs::read(&temp_path).unwrap();
        let _ = fs::remove_file(&temp_path);
        data
    }

    /// The calendar fixture's tables, without the `user_version` the provider
    /// stamps (600 on the android2022 Pixel), so a test states it explicitly.
    const CALENDAR_SQL: &str = "CREATE TABLE Calendars (_id INTEGER PRIMARY KEY, calendar_displayName TEXT);
             CREATE TABLE Events (
                 _id INTEGER PRIMARY KEY, title TEXT, description TEXT, eventLocation TEXT,
                 dtstart INTEGER, dtend INTEGER, allDay INTEGER, calendar_id INTEGER,
                 organizer TEXT, rrule TEXT
             );
             INSERT INTO Calendars VALUES (1, 'Work');
             INSERT INTO Events VALUES
                 (1, 'Standup', 'Daily sync', 'Room A', 1609459200000, 1609462800000, 0, 1, 'boss@example.com', NULL),
                 (2, 'Lunch', NULL, 'Cafe', 1609495200000, 1609498800000, 0, 1, NULL, 'FREQ=WEEKLY');";

    fn stale_markers(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["type"] == "ParserStaleWarning")
            .collect()
    }

    /// `calendar.db` was validated against one real store, `PRAGMA
    /// user_version` 600 (android2022, Android 12); a store at that version with
    /// every column present owes no stale marker.
    #[test]
    fn a_calendar_at_the_validated_version_carries_no_stale_marker() {
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", calendar_db_bytes()))
            .unwrap();
        assert!(stale_markers(&out).is_empty());
        assert_eq!(events(&out).len(), 2);
    }

    /// A newer provider version is still parsed — the events are the evidence —
    /// and the parse says the version is past what was validated.
    #[test]
    fn a_calendar_with_a_newer_schema_version_is_parsed_and_declared_stale() {
        let out = AndroidCalendarParser::new()
            .process(&artifact_with(
                "calendar.db",
                build_db(&format!("PRAGMA user_version = 700; {CALENDAR_SQL}")),
            ))
            .unwrap();
        assert_eq!(events(&out).len(), 2);
        let stale = stale_markers(&out);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].metadata["seen_schema_version"], 700);
        assert_eq!(stale[0].metadata["supported_range"], "600..=600");
        assert_eq!(stale[0].metadata["app"], "android-calendar");
        // §1.4a (decided 2026-09-26): outside the range is a disclosure.
        assert_eq!(stale[0].metadata["status"], "SchemaOutsideValidated");
        assert!(stale[0].metadata.get("content_incomplete").is_none());
        assert!(stale[0].metadata.get("content_incomplete_reason").is_none());
    }

    /// The provider always stamps `user_version`; 0 is SQLite's unset default
    /// and is stated as absent, never ranked as older than 600.
    #[test]
    fn a_calendar_with_no_recorded_version_is_stated_not_ranked() {
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", build_db(CALENDAR_SQL)))
            .unwrap();
        let stale = stale_markers(&out);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].metadata["status"], "SchemaVersionNotRecorded");
        assert!(stale[0].metadata.get("content_incomplete").is_none());
    }

    /// A renamed `dtstart` would otherwise leave every event undated with
    /// nothing saying why. The events are still emitted from what resolved,
    /// and the marker names the field.
    #[test]
    fn a_renamed_events_column_is_named_on_the_stale_marker() {
        let sql = format!("PRAGMA user_version = 600; {CALENDAR_SQL}")
            .replace("dtstart INTEGER", "dt_start INTEGER");
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", build_db(&sql)))
            .unwrap();
        assert_eq!(events(&out).len(), 2, "what resolved is still parsed");
        assert!(events(&out)
            .iter()
            .all(|e| e.metadata.get("dtstart").is_none() && e.metadata.get("dtend").is_some()));
        let stale = stale_markers(&out);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].metadata["status"], "SchemaFieldsUnresolved");
        assert_eq!(stale[0].metadata["unresolved_fields"], json!(["dtstart"]));
        assert_eq!(stale[0].metadata["source_table"], "Events");
        assert_eq!(stale[0].metadata["records_recovered"], 2);
    }

    /// `keep.db` was validated against one real store, `user_version` 95, whose
    /// `tree_entity` has no `text` column at all (the body lives in `list_item`),
    /// so `text` is optional and its absence is not drift.
    #[test]
    fn a_keep_store_at_the_validated_version_carries_no_stale_marker() {
        let out = GoogleKeepParser::new()
            .process(&artifact_with("keep.db", keep_db_bytes()))
            .unwrap();
        assert!(stale_markers(&out).is_empty());
        // The real store's shape: no `text` on `tree_entity`.
        let sql = format!("PRAGMA user_version = 95; {KEEP_SQL}")
            .replace("text TEXT, time_created", "time_created")
            .replace("'Password', 'the wifi code is hunter2', ", "'Password', ")
            .replace("'Groceries', NULL, ", "'Groceries', ");
        let out = GoogleKeepParser::new()
            .process(&artifact_with("keep.db", build_db(&sql)))
            .unwrap();
        assert!(stale_markers(&out).is_empty(), "{out:?}");
    }

    #[test]
    fn a_keep_store_with_a_newer_schema_version_is_parsed_and_declared_stale() {
        let out = GoogleKeepParser::new()
            .process(&artifact_with(
                "keep.db",
                build_db(&format!("PRAGMA user_version = 120; {KEEP_SQL}")),
            ))
            .unwrap();
        assert_eq!(
            out.iter()
                .filter(|a| a.metadata["type"] == "AndroidNote")
                .count(),
            2
        );
        let stale = stale_markers(&out);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].metadata["seen_schema_version"], 120);
        assert_eq!(stale[0].metadata["supported_range"], "95..=95");
        assert_eq!(stale[0].metadata["app"], "google-keep");
    }

    /// A renamed `list_item.text` is the checklist body gone: the notes are
    /// still listed, their items are not, and the marker names the field.
    #[test]
    fn a_renamed_keep_list_item_column_is_named_on_the_stale_marker() {
        let sql = format!("PRAGMA user_version = 95; {KEEP_SQL}").replace(
            "list_parent_id INTEGER, text TEXT",
            "list_parent_id INTEGER, body TEXT",
        );
        let out = GoogleKeepParser::new()
            .process(&artifact_with("keep.db", build_db(&sql)))
            .unwrap();
        let notes: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == "AndroidNote")
            .collect();
        assert_eq!(notes.len(), 2, "both titled notes still stand");
        let groceries = notes
            .iter()
            .find(|n| n.metadata["title"] == "Groceries")
            .unwrap();
        assert!(
            groceries.metadata.get("text").is_none(),
            "the checklist body could not be joined"
        );
        let stale = stale_markers(&out);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].metadata["status"], "SchemaFieldsUnresolved");
        assert_eq!(stale[0].metadata["unresolved_fields"], json!(["text"]));
        assert_eq!(stale[0].metadata["source_table"], "list_item");
    }

    fn calendar_db_bytes() -> Vec<u8> {
        // 2021-01-01T00:00:00Z and +1h in epoch ms.
        build_db(&format!("PRAGMA user_version = 600; {CALENDAR_SQL}"))
    }

    fn artifact_with(name: &str, bytes: Vec<u8>) -> Artifact {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": name }),
        )
    }

    fn events(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("CalendarEvent"))
            .collect()
    }

    fn find_event<'a>(out: &'a [Artifact], summary: &str) -> &'a Artifact {
        out.iter()
            .find(|a| a.metadata.get("summary").and_then(|v| v.as_str()) == Some(summary))
            .expect("event record present")
    }

    #[test]
    fn module_metadata() {
        let p = AndroidCalendarParser::new();
        assert_eq!(p.id(), "plugin.mobile.android_calendar");
        assert_eq!(p.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            p.subscribes_to(),
            vec![ArtifactType::FileEntry, ArtifactType::FileContent]
        );
        assert_eq!(p.input_capability(), InputCapability::RandomAccess);
    }

    #[test]
    fn parses_two_events_with_calendar_join() {
        let art = artifact_with("calendar.db", calendar_db_bytes());
        let parent = art.id;
        let case = art.case_id;
        let out = AndroidCalendarParser::new().process(&art).unwrap();

        let evs = events(&out);
        assert_eq!(evs.len(), 2);

        let standup = find_event(&out, "Standup");
        assert_eq!(standup.parent_id, Some(parent));
        assert_eq!(standup.case_id, case);
        assert_eq!(standup.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(standup.metadata["location"], json!("Room A"));
        assert_eq!(standup.metadata["description"], json!("Daily sync"));
        assert_eq!(standup.metadata["source"], json!("android_calendar"));
        assert_eq!(standup.metadata["organizer"], json!("boss@example.com"));
        // Calendar display name is joined in.
        assert_eq!(standup.metadata["calendar"], json!("Work"));
        assert_eq!(standup.metadata["all_day"], json!(false));
        // dtstart converted from epoch ms to an RFC3339 UTC string (ical field/unit).
        assert!(standup.metadata["dtstart"]
            .as_str()
            .unwrap()
            .starts_with("2021-01-01T00:00:00"));
        assert!(standup.metadata["dtend"]
            .as_str()
            .unwrap()
            .starts_with("2021-01-01T01:00:00"));

        let lunch = find_event(&out, "Lunch");
        assert_eq!(lunch.metadata["location"], json!("Cafe"));
        assert_eq!(lunch.metadata["recurrence"], json!("FREQ=WEEKLY"));
        // Absent description is omitted, never null.
        assert!(lunch.metadata.get("description").is_none());
        assert!(lunch.metadata.get("organizer").is_none());

        // Exactly one summary describing the file.
        let summary = out
            .iter()
            .find(|a| {
                a.metadata.get("type").and_then(|v| v.as_str()) == Some("AndroidCalendarSummary")
            })
            .expect("summary present");
        assert_eq!(summary.metadata["event_count"], json!(2));
        assert_eq!(
            summary.metadata["subtype"],
            json!("android_calendar_summary")
        );
        assert_eq!(summary.metadata["source"], json!("android_calendar"));
    }

    #[test]
    fn path_gating_matches_provider_path() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(calendar_db_bytes()));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({
                "name": "calendar.db.bak",
                "path": "/data/data/com.android.providers.calendar/databases/calendar.db.bak"
            }),
        );
        let out = AndroidCalendarParser::new().process(&art).unwrap();
        assert_eq!(events(&out).len(), 2);
    }

    #[test]
    fn gating_rejects_unrelated_filename() {
        let art = artifact_with("notes.txt", b"just some notes".to_vec());
        let out = AndroidCalendarParser::new().process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn gating_rejects_calendar_db_without_events_table() {
        // Name passes the pre-filter; only the Events-table check can reject it.
        let bytes =
            build_db("CREATE TABLE Foo (id INTEGER PRIMARY KEY); INSERT INTO Foo VALUES (1);");
        let art = artifact_with("calendar.db", bytes);
        let out = AndroidCalendarParser::new().process(&art).unwrap();
        assert!(out.is_empty(), "no Events table must yield zero artifacts");
    }

    #[test]
    fn gating_rejects_directory() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(calendar_db_bytes()));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "calendar.db", "is_directory": true }),
        );
        let out = AndroidCalendarParser::new().process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn gating_rejects_missing_data_source() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "calendar.db" }),
        );
        let out = AndroidCalendarParser::new().process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn malformed_non_sqlite_input_does_not_panic() {
        let art = artifact_with("calendar.db", vec![0xABu8; 2048]);
        let out = AndroidCalendarParser::new().process(&art).unwrap();
        assert!(out.is_empty());

        // Empty content: extraction bails, no panic.
        let art2 = artifact_with("calendar.db", Vec::new());
        let out2 = AndroidCalendarParser::new().process(&art2).unwrap();
        assert!(out2.is_empty());
    }

    /// A WAL-mode `calendar.db` whose newest event is still only in the `-wal`
    /// — the state a device seized while running is in. The shared spill must
    /// carry the sidecar across, or that event is silently lost.
    #[test]
    fn uncheckpointed_wal_events_are_parsed() {
        use seance_core::data_source::FileDataSource;

        let dir = std::env::temp_dir().join(format!("seance_cal_wal_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("calendar.db");

        // The seed connection stays open: closing it checkpoints the WAL away.
        let seed = Connection::open(&db).unwrap();
        seed.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        seed.execute_batch(
            "CREATE TABLE Calendars (_id INTEGER PRIMARY KEY, calendar_displayName TEXT);
             CREATE TABLE Events (
                 _id INTEGER PRIMARY KEY, title TEXT, description TEXT, eventLocation TEXT,
                 dtstart INTEGER, dtend INTEGER, allDay INTEGER, calendar_id INTEGER,
                 organizer TEXT, rrule TEXT
             );
             INSERT INTO Calendars VALUES (1, 'Work');
             INSERT INTO Events VALUES
                 (1, 'Checkpointed', NULL, NULL, 1609459200000, 1609462800000, 0, 1, NULL, NULL);",
        )
        .unwrap();
        seed.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        seed.execute_batch(
            "INSERT INTO Events VALUES
                 (2, 'Only in WAL', NULL, NULL, 1609495200000, 1609498800000, 0, 1, NULL, NULL);",
        )
        .unwrap();

        let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(db).unwrap());
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "calendar.db" }),
        );
        let out = AndroidCalendarParser::new().process(&art).unwrap();
        let titles: Vec<&str> = events(&out)
            .iter()
            .map(|a| a.metadata["summary"].as_str().unwrap())
            .collect();
        assert!(
            titles.contains(&"Only in WAL"),
            "uncheckpointed event must come across with the -wal sidecar, got {titles:?}"
        );

        drop(seed);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The Keep fixture's tables, without the `user_version` the app stamps
    /// (95 on the android2022 Pixel), so a test states it explicitly.
    const KEEP_SQL: &str =
        "CREATE TABLE tree_entity (_id INTEGER PRIMARY KEY, type INTEGER, title TEXT, \
             text TEXT, time_created INTEGER, user_edited_timestamp INTEGER, is_archived INTEGER, \
             is_trashed INTEGER, color_name TEXT);
             CREATE TABLE list_item (_id INTEGER PRIMARY KEY, list_parent_id INTEGER, text TEXT, \
             order_in_parent INTEGER);
             INSERT INTO tree_entity VALUES (1, 0, 'Password', 'the wifi code is hunter2', \
             1700000000000000, 1700000500000000, 0, 0, 'BLUE');
             INSERT INTO tree_entity VALUES (2, 1, 'Groceries', NULL, 1700000000000000, \
             1700000000000000, 1, 0, 'RED');
             INSERT INTO list_item VALUES (10, 2, 'milk', 0);
             INSERT INTO list_item VALUES (11, 2, 'eggs', 1);";

    fn keep_db_bytes() -> Vec<u8> {
        build_db(&format!("PRAGMA user_version = 95; {KEEP_SQL}"))
    }

    #[test]
    fn parses_keep_notes_and_list_items() {
        let art = artifact_with("keep.db", keep_db_bytes());
        let out = GoogleKeepParser::new().process(&art).unwrap();
        assert_eq!(out.len(), 2);

        let pw = out
            .iter()
            .find(|a| a.metadata["title"] == "Password")
            .unwrap();
        assert_eq!(pw.metadata["type"], "AndroidNote");
        assert_eq!(pw.metadata["source"], "google_keep");
        assert_eq!(pw.metadata["text"], "the wifi code is hunter2");
        assert!(pw.metadata["created_rfc3339"]
            .as_str()
            .unwrap()
            .starts_with("2023-"));
        // `created` is normalized to Unix seconds, not the raw µs value.
        // 1_700_000_000_000_000 µs / 1_000_000 == 1_700_000_000 s.
        assert_eq!(pw.metadata["created"].as_i64(), Some(1_700_000_000));

        // List note: text assembled from list_item rows, in order.
        let groc = out
            .iter()
            .find(|a| a.metadata["title"] == "Groceries")
            .unwrap();
        assert_eq!(groc.metadata["text"], "milk\neggs");
        assert_eq!(groc.metadata["note_type"], "list");
        assert_eq!(groc.metadata["is_archived"], true);
    }

    #[test]
    fn keep_gating_rejects_non_keep() {
        let art = artifact_with("notes.txt", b"hello".to_vec());
        assert!(GoogleKeepParser::new().process(&art).unwrap().is_empty());
        // A keep.db without a tree_entity table is not the Keep store.
        let art2 = artifact_with("keep.db", build_db("CREATE TABLE x (a INTEGER);"));
        assert!(GoogleKeepParser::new().process(&art2).unwrap().is_empty());
    }

    // --- Cap honesty (B2-050 / B2-081) ------------------------------------

    /// A calendar walk that ran to completion must not claim to be truncated.
    #[test]
    fn a_complete_calendar_summary_is_not_marked_incomplete() {
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", calendar_db_bytes()))
            .unwrap();
        let summary = out
            .iter()
            .find(|a| a.metadata["type"] == "AndroidCalendarSummary")
            .expect("summary record");
        assert_eq!(summary.metadata["event_count"], json!(2));
        assert!(summary.metadata.get("truncated").is_none());
        assert!(summary.metadata.get("content_incomplete").is_none());
    }

    /// The cap marker states plainly that the extracted set is a prefix, so a
    /// capped calendar or notebook cannot present itself as complete.
    #[test]
    fn the_cap_marker_states_that_the_extraction_stopped_short() {
        let a = cap_marker(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "AndroidNoteParseStatus",
            "android_note_incomplete",
            "google_keep",
            "keep.db",
            MAX_EVENT_ENTRIES,
            MAX_EVENT_ENTRIES,
            "Google Keep notes beyond the parser cap were not extracted",
        );
        assert_eq!(a.metadata["truncated"], json!(true));
        assert_eq!(a.metadata["content_incomplete"], json!(true));
        assert_eq!(a.metadata["content_incomplete_reason"], "cap_reached");
        assert_eq!(a.metadata["extracted_count"], json!(MAX_EVENT_ENTRIES));
        assert_eq!(a.metadata["max_entries"], json!(MAX_EVENT_ENTRIES));
        assert_eq!(a.metadata["file_name"], "keep.db");
    }

    // --- Outer spill honesty (B3-013) -------------------------------------
    fn truncated_artifact(name: &str, bytes: Vec<u8>) -> Artifact {
        let ds: Arc<dyn DataSource> = Arc::new(truncated(bytes));
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": name }),
        )
    }

    /// B3-013: the row caps were flagged but the OUTER shortfall — the database
    /// file itself not staged in full — was not, so a partial calendar parsed
    /// as a complete one. What an examiner learns: whether the events listed
    /// are all of them. A wrong answer here reads as "no meeting was scheduled".
    #[test]
    fn a_short_read_marks_every_calendar_event_it_produced() {
        let out = AndroidCalendarParser::new()
            .process(&truncated_artifact("calendar.db", calendar_db_bytes()))
            .unwrap();
        let ev = events(&out);
        assert!(!ev.is_empty(), "the readable prefix still parses");
        for a in &ev {
            assert_eq!(a.metadata["content_incomplete"], json!(true));
            assert_eq!(a.metadata["content_incomplete_reason"], "short_read");
        }
        assert!(
            out.iter()
                .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                    == Some("DatabaseNotStagedInFull")),
            "a partial spill must be reported in its own right"
        );
    }

    /// The same for Keep: a partial notebook must not read as the whole one.
    #[test]
    fn a_short_read_marks_every_keep_note_it_produced() {
        let out = GoogleKeepParser::new()
            .process(&truncated_artifact("keep.db", keep_db_bytes()))
            .unwrap();
        let notes: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("AndroidNote"))
            .collect();
        assert!(!notes.is_empty(), "the readable prefix still parses");
        for a in &notes {
            assert_eq!(a.metadata["content_incomplete"], json!(true));
            assert_eq!(a.metadata["content_incomplete_reason"], "short_read");
        }
        assert!(
            out.iter()
                .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                    == Some("DatabaseNotStagedInFull")),
            "a partial spill must be reported in its own right"
        );
    }

    /// A database staged in full stays unmarked, or the marker means nothing.
    #[test]
    fn a_whole_calendar_database_carries_no_spill_incompleteness() {
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", calendar_db_bytes()))
            .unwrap();
        assert!(!out.is_empty());
        assert!(out
            .iter()
            .all(|a| a.metadata.get("content_incomplete").is_none()));
    }

    /// A truncation deep enough to hide the signature table must still say so:
    /// "we could not read far enough to find `Events`" and "this is not an
    /// Android calendar" are different findings.
    #[test]
    fn a_short_read_that_hides_the_signature_table_is_still_reported() {
        let bytes = build_db("CREATE TABLE Foo (id INTEGER PRIMARY KEY);");
        let out = AndroidCalendarParser::new()
            .process(&truncated_artifact("calendar.db", bytes))
            .unwrap();
        assert!(
            out.iter()
                .any(|a| a.metadata.get("status").and_then(|v| v.as_str())
                    == Some("DatabaseNotStagedInFull")),
            "a short spill with no recognisable schema must not be silent"
        );
    }
    /// A calendar-display-name row that will not decode must be counted.
    ///
    /// What an examiner learns: which calendar an appointment was on. A dropped
    /// `Calendars` row re-attributes every event on that calendar to no
    /// calendar at all, and the summary used to report the same event count
    /// with nothing saying the labels were lost (B4-014).
    #[test]
    fn undecodable_calendar_name_rows_are_declared_on_the_summary() {
        // `_id` is read as i64; a text primary key value makes the row fail to
        // map while the events themselves stay sound.
        let bytes = build_db(
            "CREATE TABLE Calendars (_id BLOB, calendar_displayName TEXT);
             CREATE TABLE Events (
                 _id INTEGER PRIMARY KEY, title TEXT, description TEXT, eventLocation TEXT,
                 dtstart INTEGER, dtend INTEGER, allDay INTEGER, calendar_id INTEGER,
                 organizer TEXT, rrule TEXT
             );
             INSERT INTO Calendars VALUES (x'deadbeef', 'Work');
             INSERT INTO Events VALUES
                 (1, 'Standup', NULL, NULL, 1609459200000, 1609462800000, 0, 1, NULL, NULL);",
        );
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", bytes))
            .unwrap();

        let summary = out
            .iter()
            .find(|a| {
                a.metadata.get("type").and_then(|v| v.as_str()) == Some("AndroidCalendarSummary")
            })
            .expect("summary record");
        assert_eq!(summary.metadata["event_count"], json!(1));
        assert_eq!(summary.metadata["calendar_names_dropped"], json!(1));
        assert_eq!(summary.metadata["content_incomplete"], json!(true));
        assert_eq!(summary.metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            summary.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
    }

    /// A clean calendar reports zero drops and claims nothing about being
    /// incomplete.
    #[test]
    fn a_clean_calendar_summary_reports_no_dropped_rows() {
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", calendar_db_bytes()))
            .unwrap();
        let summary = out
            .iter()
            .find(|a| {
                a.metadata.get("type").and_then(|v| v.as_str()) == Some("AndroidCalendarSummary")
            })
            .expect("summary record");
        assert_eq!(summary.metadata["event_rows_dropped"], json!(0));
        assert_eq!(summary.metadata["calendar_names_dropped"], json!(0));
        assert!(summary.metadata.get("content_incomplete").is_none());
    }

    /// A checklist line that will not decode marks the note it belongs to.
    ///
    /// What an examiner learns: the content of a note. A dropped `list_item`
    /// row removes a line the custodian wrote from a note body that still reads
    /// as complete (B4-033).
    #[test]
    fn undecodable_checklist_rows_mark_the_note_incomplete() {
        let bytes = build_db(
            "CREATE TABLE tree_entity (_id INTEGER PRIMARY KEY, title TEXT, text TEXT, \
                 type INTEGER, time_created INTEGER, user_edited_timestamp INTEGER, \
                 is_trashed INTEGER, is_archived INTEGER, color_name TEXT);
             CREATE TABLE list_item (_id INTEGER PRIMARY KEY, list_parent_id INTEGER, \
                 text BLOB, order_in_parent INTEGER);
             INSERT INTO tree_entity VALUES (1, 'Shopping', NULL, 1, 1609459200000, \
                 1609459200000, 0, 0, NULL);
             INSERT INTO list_item VALUES (1, 1, 'milk', 0);
             INSERT INTO list_item VALUES (2, 1, x'deadbeef', 1);",
        );
        let out = GoogleKeepParser::new()
            .process(&artifact_with("keep.db", bytes))
            .unwrap();

        let note = out
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("AndroidNote"))
            .expect("the note is still recovered");
        assert_eq!(note.metadata["list_items_dropped"], json!(1));
        assert_eq!(note.metadata["content_incomplete"], json!(true));
        assert_eq!(
            note.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert!(
            note.metadata["text"]
                .as_str()
                .is_some_and(|t| t.contains("milk")),
            "the line that did decode is still evidence: {:?}",
            note.metadata["text"]
        );

        // And the walk-level marker names the loss too.
        let marker = out
            .iter()
            .find(|a| a.metadata.get("status").and_then(|v| v.as_str()) == Some("RowsUndecodable"))
            .expect("a walk-level marker");
        assert_eq!(marker.metadata["secondary_rows_dropped"], json!(1));
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
    }

    // --- B8-039: a schema probe that fails closed into a positive claim ---

    /// Damage page 1's b-tree without touching the file header, so the database
    /// OPENS and then answers every catalogue query with `SQLITE_CORRUPT` — the
    /// state a carved or partially recovered provider database arrives in.
    ///
    /// Bytes 103..105 are page 1's b-tree cell count; SQLite rejects a page
    /// whose cell count exceeds `(page_size - 8) / 6`.
    fn corrupt_the_catalogue(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes[103] = 0xFF;
        bytes[104] = 0xFF;
        bytes
    }

    /// B8-039. `table_exists` ended in `.unwrap_or(false)`, so a catalogue read
    /// that failed on a damaged `calendar.db` was indistinguishable from "there
    /// is no Events table" — and the parser returned nothing, which reads as a
    /// custodian who kept no appointments.
    ///
    /// Against the unfixed code this returns an empty vector.
    #[test]
    fn a_corrupt_calendar_store_is_not_reported_as_a_device_with_no_events() {
        let art = artifact_with("calendar.db", corrupt_the_catalogue(calendar_db_bytes()));
        let out = AndroidCalendarParser::new().process(&art).unwrap();

        assert!(
            !out.is_empty(),
            "an unreadable calendar store must not render as one with no events"
        );
        let marker = out
            .iter()
            .find(|a| a.metadata["subtype"] == json!("parse_incomplete"))
            .expect("the store was identified and not examined; that must be stated");
        assert_eq!(marker.metadata["type"], json!("AndroidCalendarIncomplete"));
        assert_ne!(
            marker.metadata["type"],
            json!("CalendarEvent"),
            "a marker filed under the record type would be shown as an appointment"
        );
        assert_eq!(marker.metadata["status"], json!("StoreUnreadable"));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
        assert!(
            events(&out).is_empty(),
            "no events were invented to go with it"
        );
    }

    /// The same defect on the Keep surface.
    #[test]
    fn a_corrupt_keep_store_is_not_reported_as_a_device_with_no_notes() {
        let art = artifact_with("keep.db", corrupt_the_catalogue(keep_db_bytes()));
        let out = GoogleKeepParser::new().process(&art).unwrap();

        assert!(
            !out.is_empty(),
            "an unreadable notebook must not render as an empty one"
        );
        let marker = out
            .iter()
            .find(|a| a.metadata["status"] == json!("StoreUnreadable"))
            .expect("an unreadable keep.db must be declared");
        assert_eq!(marker.metadata["type"], json!("AndroidNoteIncomplete"));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert!(!out
            .iter()
            .any(|a| a.metadata["type"] == json!("AndroidNote")));
    }

    /// The control that gives those markers their meaning: a readable database
    /// whose catalogue ANSWERED "no Events table" is a finding, and silence is
    /// the right answer to it.
    #[test]
    fn a_readable_database_without_events_still_produces_nothing() {
        let art = artifact_with(
            "calendar.db",
            build_db("CREATE TABLE unrelated (a INTEGER);"),
        );
        assert!(AndroidCalendarParser::new()
            .process(&art)
            .unwrap()
            .is_empty());
    }

    /// And a file that is not a database at all keeps the old silence: the
    /// filename gate is permissive, so claiming an unreadable provider store for
    /// any file named `calendar.db` would manufacture the opposite error.
    #[test]
    fn a_non_sqlite_file_named_calendar_db_is_still_ignored() {
        let art = artifact_with(
            "calendar.db",
            b"this is a text file, not a database".to_vec(),
        );
        assert!(AndroidCalendarParser::new()
            .process(&art)
            .unwrap()
            .is_empty());
    }

    /// A healthy calendar parse must carry no schema marker, or the marker means
    /// nothing.
    #[test]
    fn a_healthy_calendar_parse_carries_no_schema_marker() {
        let art = artifact_with("calendar.db", calendar_db_bytes());
        let out = AndroidCalendarParser::new().process(&art).unwrap();
        assert_eq!(events(&out).len(), 2);
        assert!(!out
            .iter()
            .any(|a| a.metadata["status"] == json!("SchemaUndetermined")));
    }

    /// HUNT-187. The provider writes 0 into `dtstart`/`dtend` for an event it
    /// holds no time for; converting it gave `1970-01-01T00:00:00Z`, a date the
    /// custodian never entered, against the crate doc's "omitted rather than
    /// fabricated".
    #[test]
    fn a_zero_event_time_is_omitted_not_written_as_1970() {
        let sql = format!("PRAGMA user_version = 600; {CALENDAR_SQL}")
            .replace("1609495200000, 1609498800000", "0, 0");
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", build_db(&sql)))
            .unwrap();
        let lunch = find_event(&out, "Lunch");
        assert!(
            lunch.metadata.get("dtstart").is_none() && lunch.metadata.get("dtend").is_none(),
            "a zero time is unset, not the Unix epoch: {:?}",
            lunch.metadata
        );
        // The non-zero event is unaffected.
        assert_eq!(
            find_event(&out, "Standup").metadata["dtstart"],
            "2021-01-01T00:00:00Z"
        );
    }

    /// HUNT-187. `_id` was read unplanned on the belief that "SQLite provides
    /// the rowid whether or not the column is declared" — true of `rowid`, not
    /// of `_id`, so an `Events` table without an `_id` column failed the whole
    /// query. The events are read by `rowid` instead.
    #[test]
    fn an_events_table_without_an_id_column_is_still_read() {
        let sql = format!("PRAGMA user_version = 600; {CALENDAR_SQL}")
            .replace(
                "CREATE TABLE Events (\n                 _id INTEGER PRIMARY KEY, title",
                // forensic-lint: allow RAGGED-STRING — matches the fixture SQL's indentation.
                "CREATE TABLE Events (\n                 title",
            )
            .replace("(1, 'Standup'", "('Standup'")
            .replace("(2, 'Lunch'", "('Lunch'");
        assert!(!sql.contains("(1, 'Standup'"), "fixture rewrite applied");
        let out = AndroidCalendarParser::new()
            .process(&artifact_with("calendar.db", build_db(&sql)))
            .unwrap();
        assert_eq!(events(&out).len(), 2, "{out:?}");
        assert_eq!(find_event(&out, "Standup").metadata["rowid"], 1);
    }

    /// An `Events` that is listed in the catalogue but whose column list will
    /// not read — here a view over a table that has since gone — is the store
    /// identified and not examined.
    const BROKEN_EVENTS_VIEW_SQL: &str = "PRAGMA user_version = 600;
         CREATE TABLE Calendars (_id INTEGER PRIMARY KEY, calendar_displayName TEXT);
         CREATE TABLE ev (_id INTEGER PRIMARY KEY, title TEXT);
         CREATE VIEW Events AS SELECT _id, title FROM ev;
         DROP TABLE ev;";

    /// HUNT-187. Every prepare or column-list failure inside `parse_calendar`
    /// became `ModuleError::ParsingError` — an error row and no artifact —
    /// instead of the `B8-038`/`B8-039` marker the same function claims.
    #[test]
    fn a_calendar_whose_events_cannot_be_queried_is_reported_unreadable_not_an_error() {
        let art = artifact_with("calendar.db", build_db(BROKEN_EVENTS_VIEW_SQL));
        let out = AndroidCalendarParser::new()
            .process(&art)
            .expect("a store that cannot be queried is a finding, not a module error");
        let marker = out
            .iter()
            .find(|a| a.metadata["status"] == json!("StoreUnreadable"))
            .expect("the unread store is declared");
        assert_eq!(marker.metadata["type"], json!("AndroidCalendarIncomplete"));
        assert_eq!(marker.metadata["content_incomplete"], json!(true));
        assert_eq!(marker.metadata["inventory_incomplete"], json!(true));
        assert!(
            marker.metadata["detail"]
                .as_str()
                .unwrap()
                .contains("Events"),
            "{:?}",
            marker.metadata
        );
        assert!(events(&out).is_empty());
    }

    /// The same on the Keep surface.
    #[test]
    fn a_keep_store_whose_notes_cannot_be_queried_is_reported_unreadable_not_an_error() {
        let sql = "PRAGMA user_version = 95;
             CREATE TABLE te (_id INTEGER PRIMARY KEY, title TEXT);
             CREATE VIEW tree_entity AS SELECT _id, title FROM te;
             DROP TABLE te;";
        let out = GoogleKeepParser::new()
            .process(&artifact_with("keep.db", build_db(sql)))
            .expect("a store that cannot be queried is a finding, not a module error");
        let marker = out
            .iter()
            .find(|a| a.metadata["status"] == json!("StoreUnreadable"))
            .expect("the unread notebook is declared");
        assert_eq!(marker.metadata["type"], json!("AndroidNoteIncomplete"));
        assert!(marker.metadata["detail"]
            .as_str()
            .unwrap()
            .contains("tree_entity"));
        assert!(!out
            .iter()
            .any(|a| a.metadata["type"] == json!("AndroidNote")));
    }

    /// HUNT-187. A `calendar.db`/`keep.db` that SQLite would not open returned
    /// `Ok(Vec::new())` although the name had already established the store.
    /// `Connection::open` is lazy and cannot be made to fail from a fixture, so
    /// the branch's body is pinned directly: a staged file carrying the SQLite
    /// header gets the marker; one that does not keeps the old silence.
    #[test]
    fn a_store_that_will_not_open_is_declared_when_it_is_a_database() {
        let (case, parent) = (Uuid::new_v4(), Uuid::new_v4());
        let db = TempDb::write(&calendar_db_bytes(), "t").unwrap();
        let out = store_would_not_open(
            case,
            parent,
            &db,
            "AndroidCalendarIncomplete",
            "calendar.db",
            "calendar events",
            &"unable to open database file",
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["status"], json!("StoreUnreadable"));
        assert_eq!(out[0].metadata["type"], json!("AndroidCalendarIncomplete"));
        assert!(out[0].metadata["detail"]
            .as_str()
            .unwrap()
            .contains("unable to open database file"));

        let not_db = TempDb::write(b"plain text, not a database", "t").unwrap();
        assert!(store_would_not_open(
            case,
            parent,
            &not_db,
            "AndroidCalendarIncomplete",
            "calendar.db",
            "calendar events",
            &"file is not a database",
        )
        .is_empty());
    }
}
