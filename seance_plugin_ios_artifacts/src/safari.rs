//! Safari on iOS: saved bookmarks, open tabs and recent web searches.
//!
//! Three stores, three readers, because on a real device they do not live
//! where a reference says they do:
//!
//! * `Bookmarks.db` holds saved bookmarks and the reading list. Its
//!   `bookmarks` table is **byte-identical** to the one in `SafariTabs.db`,
//!   so the basename is not what tells them apart — the `windows` table is.
//! * Open tabs moved between generations: iOS 13/14 keeps them in
//!   `BrowserState.db` (`tabs`), iOS 15+ in `SafariTabs.db` (`bookmarks` rows
//!   under a tab-group folder). A device carries both files, and on iOS 15
//!   the older one has an empty `tabs` table — which is not "no tabs were
//!   open" and must not be reported as such.
//! * Recent searches are not in `RecentSearches.plist`; they are the
//!   `RecentWebSearches` array of the app's own `com.apple.mobilesafari.plist`,
//!   inside its container. The key is what selects the file, not its path.
//!
//! Every count and shape here was read from the Magnet 2022 iOS 15 device
//! before the code was written (`tests/fixtures/magnet2022_ios15`).

use std::collections::HashMap;
use std::io::Cursor;

use rusqlite::Connection;
use seance_core::io::{read_full, IncompleteReason};
use seance_core::time::unix_ns;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::stale::{check_schema_version, SupportedRange};
use seance_sqlite_util::RowDrops;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    basename, cfloat, cint, cstr, has_table, insert_cocoa, parent_record, query_unusable_artifact,
    table_count_checked, with_db,
};

/// `PRAGMA user_version` of the one `Bookmarks.db` / `SafariTabs.db`
/// generation these readers were validated against (iOS 15.0, 19A404). A
/// file outside the range still parses; it carries a `ParserStaleWarning`.
const SAFARI_BOOKMARKS_SCHEMA: SupportedRange = SupportedRange {
    min: 43,
    max: Some(43),
};
/// `PRAGMA user_version` of the `BrowserState.db` generation held.
const BROWSER_STATE_SCHEMA: SupportedRange = SupportedRange {
    min: 5,
    max: Some(5),
};

/// Ceiling on the preferences plist: the real one is 3.5 KB.
const MAX_SEARCHES_PLIST_BYTES: u64 = 16 * 1024 * 1024;
/// Ceiling on a tab's back/forward list carried into the case.
const MAX_SESSION_HISTORY_ENTRIES: usize = 500;
/// Ceiling on folder-walk depth when building a bookmark's folder path.
const MAX_FOLDER_DEPTH: usize = 32;

const LAST_VISIT_SOURCE: &str = "bookmarks.local_attributes[LastVisitTime] (plist date, Apple Cocoa seconds since 2001-01-01, converted to Unix)";
const SEARCH_DATE_SOURCE: &str =
    "RecentWebSearches[].Date (plist date, Apple Cocoa seconds since 2001-01-01, converted to Unix)";

/// The real store the `43..=43` range was read out of.
const SAFARI_BOOKMARKS_EVIDENCE: &str =
    "Magnet 2022 CTF iPhone 8 (iOS 15.0, 19A404) Library/Safari/Bookmarks.db and SafariTabs.db";
/// The real store the `5..=5` range was read out of.
const BROWSER_STATE_EVIDENCE: &str =
    "Magnet 2022 CTF iPhone 8 (iOS 15.0, 19A404) Library/Safari/BrowserState.db";

/// The schema record this store owes, or `None` only when its recorded
/// `PRAGMA user_version` lies inside `range`.
///
/// Every answer the shared check can give is disposed of here: a version of
/// 0 is "not recorded" (SQLite's unset default, never ranked as OLDER) and a
/// pragma that would not read is "undetermined" — both a record, where the
/// `_ => None` arm this replaced made each of them silence (HUNT-186).
fn schema_marker(
    conn: &Connection,
    app: &str,
    range: &SupportedRange,
    evidence: &str,
    case: Uuid,
    parent: Uuid,
) -> Option<Artifact> {
    check_schema_version(conn, app, range).marker(case, parent, Some(evidence))
}

fn user_version(conn: &Connection) -> Option<i64> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0)).ok()
}

/// The role a `special_id` gives a folder, as Safari itself names them.
fn special_role(special_id: i64) -> Option<&'static str> {
    match special_id {
        1 => Some("bookmarks_bar"),
        3 => Some("reading_list"),
        5 => Some("frequently_visited"),
        _ => None,
    }
}

/// One `bookmarks` row, from either Safari database.
struct BookmarkRow {
    id: i64,
    special_id: i64,
    parent: Option<i64>,
    kind: Option<i64>,
    title: Option<String>,
    url: Option<String>,
    num_children: Option<i64>,
    hidden: bool,
    deleted: bool,
    read: Option<i64>,
    last_modified: Option<f64>,
    order_index: Option<i64>,
    external_uuid: Option<String>,
    date_closed: Option<f64>,
    extra_len: i64,
    local_len: i64,
    sync_len: i64,
}

/// The `bookmarks` rows, or the error SQLite gave for the statement — on a
/// generation missing a column that is "no such column", and the caller
/// publishes it rather than an empty store.
fn read_bookmark_rows(conn: &Connection) -> rusqlite::Result<(Vec<BookmarkRow>, RowDrops)> {
    let mut stmt = conn.prepare(
        "SELECT id, special_id, parent, type, title, url, num_children, hidden, deleted, \
                read, last_modified, order_index, external_uuid, date_closed, \
                length(extra_attributes), length(local_attributes), length(sync_data) \
         FROM bookmarks ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(BookmarkRow {
            id: cint(r, 0).unwrap_or(-1),
            special_id: cint(r, 1).unwrap_or(0),
            parent: cint(r, 2),
            kind: cint(r, 3),
            title: cstr(r, 4),
            url: cstr(r, 5),
            num_children: cint(r, 6),
            hidden: cint(r, 7).unwrap_or(0) != 0,
            deleted: cint(r, 8).unwrap_or(0) != 0,
            read: cint(r, 9),
            last_modified: cfloat(r, 10),
            order_index: cint(r, 11),
            external_uuid: cstr(r, 12),
            date_closed: cfloat(r, 13),
            extra_len: cint(r, 14).unwrap_or(0),
            local_len: cint(r, 15).unwrap_or(0),
            sync_len: cint(r, 16).unwrap_or(0),
        })
    })?;
    let mut out = Vec::new();
    let mut drops = RowDrops::default();
    for row in rows {
        match row {
            Ok(r) => out.push(r),
            Err(e) => drops.record(&e),
        }
    }
    Ok((out, drops))
}

/// `Root/BookmarksBar/...`: the titles from the row up to the root, oldest
/// first. Stops at [`MAX_FOLDER_DEPTH`] so a cyclic `parent` cannot loop.
fn folder_path(rows: &HashMap<i64, &BookmarkRow>, start: Option<i64>) -> String {
    let mut parts = Vec::new();
    let mut cur = start;
    while let Some(id) = cur {
        if parts.len() >= MAX_FOLDER_DEPTH {
            break;
        }
        let Some(row) = rows.get(&id) else { break };
        parts.push(row.title.clone().unwrap_or_else(|| format!("#{id}")));
        if row.parent == Some(id) {
            break;
        }
        cur = row.parent;
    }
    parts.reverse();
    parts.join("/")
}

// --- Bookmarks.db ------------------------------------------------------------

/// Saved bookmarks and the reading list (`Bookmarks.db`).
pub struct SafariBookmarksParser;

impl ForensicsModule for SafariBookmarksParser {
    fn id(&self) -> &str {
        "plugin.ios.safari_bookmarks"
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
            &["bookmarks.db"],
            "safari_bm",
            |conn, _ds, case, parent| {
                if !has_table(conn, "bookmarks") {
                    return Vec::new();
                }
                let mut out = Vec::new();
                // The same `bookmarks` table is what SafariTabs.db keeps its
                // open tabs in. A file with a `windows` table is that store,
                // whatever it is called, and three open tabs must not be
                // published as three saved favourites.
                if has_table(conn, "windows") {
                    let mut s = Map::new();
                    s.insert("type".into(), json!("SafariBookmarksSummary"));
                    s.insert("platform".into(), json!("iOS"));
                    s.insert("not_a_bookmarks_store".into(), json!(true));
                    s.insert("records_recovered".into(), json!(0));
                    s.insert(
                        "detail".into(),
                        json!("this file carries a `windows` table: it is the open-tabs store (SafariTabs.db), read by plugin.ios.safari_tabs"),
                    );
                    s.insert(
                        "name".into(),
                        json!("Safari bookmarks: not a bookmarks store"),
                    );
                    out.push(parent_record(case, parent, Value::Object(s)));
                    return out;
                }
                if let Some(m) = schema_marker(
                    conn,
                    "Safari Bookmarks.db",
                    &SAFARI_BOOKMARKS_SCHEMA,
                    SAFARI_BOOKMARKS_EVIDENCE,
                    case,
                    parent,
                ) {
                    out.push(m);
                }
                let (rows, drops) = match read_bookmark_rows(conn) {
                    Ok(v) => v,
                    Err(e) => {
                        out.push(query_unusable_artifact(
                            case,
                            parent,
                            "Bookmarks.db",
                            "bookmarks",
                            &e,
                        ));
                        return out;
                    }
                };
                let by_id: HashMap<i64, &BookmarkRow> = rows.iter().map(|r| (r.id, r)).collect();
                let reading_list_folder = rows.iter().find(|r| r.special_id == 3).map(|r| r.id);

                let mut bookmarks = 0usize;
                let mut folders = 0usize;
                let mut reading_list_items = 0usize;
                let mut deleted_rows = 0usize;
                let mut hidden_rows = 0usize;
                let mut dated_rows = 0usize;
                let mut blob_bytes = 0i64;
                for r in &rows {
                    blob_bytes += r.extra_len + r.local_len + r.sync_len;
                    if r.deleted {
                        deleted_rows += 1;
                    }
                    if r.hidden {
                        hidden_rows += 1;
                    }
                    if r.last_modified.is_some() {
                        dated_rows += 1;
                    }
                    let mut m = Map::new();
                    m.insert("platform".into(), json!("iOS"));
                    m.insert("source".into(), json!("Bookmarks.db"));
                    m.insert("bookmark_id".into(), json!(r.id));
                    if let Some(p) = r.parent {
                        m.insert("parent_id".into(), json!(p));
                    }
                    if let Some(t) = &r.title {
                        m.insert("title".into(), json!(t));
                    }
                    if let Some(o) = r.order_index {
                        m.insert("order_index".into(), json!(o));
                    }
                    if let Some(u) = &r.external_uuid {
                        m.insert("external_uuid".into(), json!(u));
                    }
                    m.insert("hidden".into(), json!(r.hidden));
                    m.insert("deleted".into(), json!(r.deleted));
                    if let Some(lm) = r.last_modified {
                        insert_cocoa(&mut m, "last_modified", lm, "bookmarks.last_modified");
                    }
                    match r.kind {
                        Some(1) => {
                            folders += 1;
                            m.insert("type".into(), json!("SafariBookmarkFolder"));
                            m.insert("subtype".into(), json!("safari_bookmark_folder"));
                            m.insert("special_id".into(), json!(r.special_id));
                            if let Some(role) = special_role(r.special_id) {
                                m.insert("special_role".into(), json!(role));
                            }
                            m.insert("num_children".into(), json!(r.num_children.unwrap_or(0)));
                            let path = folder_path(&by_id, Some(r.id));
                            m.insert("folder_path".into(), json!(path));
                            m.insert(
                                "name".into(),
                                json!(format!(
                                    "Safari folder: {}",
                                    r.title.as_deref().unwrap_or("(untitled)")
                                )),
                            );
                        }
                        _ => {
                            bookmarks += 1;
                            let in_reading_list =
                                reading_list_folder.is_some() && r.parent == reading_list_folder;
                            if in_reading_list {
                                reading_list_items += 1;
                            }
                            m.insert("type".into(), json!("SafariBookmark"));
                            m.insert("subtype".into(), json!("safari_bookmark"));
                            if let Some(u) = &r.url {
                                m.insert("url".into(), json!(u));
                            }
                            m.insert("reading_list".into(), json!(in_reading_list));
                            // `read` is a tri-state: NULL means Safari never
                            // recorded it, and the field is then absent rather
                            // than defaulted to unread.
                            if let Some(read) = r.read {
                                m.insert("read".into(), json!(read != 0));
                            }
                            if let Some(dc) = r.date_closed {
                                insert_cocoa(&mut m, "date_closed", dc, "bookmarks.date_closed");
                            }
                            m.insert("folder_path".into(), json!(folder_path(&by_id, r.parent)));
                            if let Some(p) = r.parent.and_then(|p| by_id.get(&p)) {
                                if let Some(t) = &p.title {
                                    m.insert("parent_title".into(), json!(t));
                                }
                            }
                            m.insert(
                                "name".into(),
                                json!(r
                                    .title
                                    .clone()
                                    .or_else(|| r.url.clone())
                                    .unwrap_or_else(|| "Safari bookmark".into())),
                            );
                        }
                    }
                    out.push(parent_record(case, parent, Value::Object(m)));
                }

                let mut s = Map::new();
                s.insert("type".into(), json!("SafariBookmarksSummary"));
                s.insert("platform".into(), json!("iOS"));
                s.insert("source".into(), json!("Bookmarks.db"));
                s.insert("bookmarks".into(), json!(bookmarks));
                s.insert("folders".into(), json!(folders));
                s.insert("reading_list_items".into(), json!(reading_list_items));
                s.insert(
                    "reading_list_folder_present".into(),
                    json!(reading_list_folder.is_some()),
                );
                s.insert("deleted_rows".into(), json!(deleted_rows));
                s.insert("hidden_rows".into(), json!(hidden_rows));
                s.insert("rows_with_last_modified".into(), json!(dated_rows));
                s.insert("rows_dropped".into(), json!(drops.dropped()));
                if let Some(v) = user_version(conn) {
                    s.insert("schema_version".into(), json!(v));
                }
                // `extra_attributes` / `local_attributes` / `sync_data` are
                // embedded plists and sync payloads. They are in the evidence
                // and this reader does not decode them; the bytes are counted
                // so "unread" is a number, not a silence.
                s.insert("attribute_blobs_decoded".into(), json!(false));
                s.insert("attribute_blob_bytes".into(), json!(blob_bytes));
                s.insert("records_recovered".into(), json!(bookmarks + folders));
                if drops.dropped() > 0 {
                    s.insert("inventory_incomplete".into(), json!(true));
                    s.insert(
                        "inventory_incomplete_reason".into(),
                        json!(IncompleteReason::UnresolvedStructure.as_str()),
                    );
                    if let Some(e) = drops.first_error() {
                        s.insert("inventory_incomplete_detail".into(), json!(e));
                    }
                }
                s.insert(
                    "name".into(),
                    json!(format!("Safari bookmarks: {bookmarks} bookmark(s), {folders} folder(s), {reading_list_items} reading-list item(s)")),
                );
                out.push(parent_record(case, parent, Value::Object(s)));
                out
            },
        ))
    }
}

// --- Open tabs: SafariTabs.db (iOS 15+) and BrowserState.db (iOS 13/14) ------

/// Open tabs, from whichever generation of store the device wrote.
pub struct SafariTabsParser;

impl ForensicsModule for SafariTabsParser {
    fn id(&self) -> &str {
        "plugin.ios.safari_tabs"
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
            &["safaritabs.db", "browserstate.db"],
            "safari_tabs",
            |conn, _ds, case, parent| {
                // The table set, not the basename, picks the generation.
                if has_table(conn, "windows") && has_table(conn, "bookmarks") {
                    safari_tabs_generation(conn, case, parent)
                } else if has_table(conn, "tabs") && has_table(conn, "browser_windows") {
                    browser_state_generation(conn, case, parent)
                } else {
                    Vec::new()
                }
            },
        ))
    }
}

/// What a tab's `local_attributes` plist says about it.
#[derive(Default)]
struct TabAttributes {
    last_visit: Option<(i64, u32)>,
    opened_from_link: Option<bool>,
    showing_reader: Option<bool>,
    tab_index: Option<i64>,
    session_state_bytes: Option<usize>,
    session_history: Option<SessionHistory>,
}

struct SessionHistory {
    current_index: Option<i64>,
    entries: Vec<Value>,
    total_entries: usize,
}

/// A plist date to Unix `(seconds, nanos)`. The plist crate hands it over as
/// a `SystemTime` built from the stored double, fraction intact.
fn plist_date_to_unix(d: plist::Date) -> Option<(i64, u32)> {
    let st: std::time::SystemTime = d.into();
    let dur = st.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some((i64::try_from(dur.as_secs()).ok()?, dur.subsec_nanos()))
}

fn read_tab_attributes(blob: &[u8]) -> TabAttributes {
    let mut attrs = TabAttributes::default();
    let Ok(v) = plist::Value::from_reader(Cursor::new(blob)) else {
        return attrs;
    };
    let Some(d) = v.as_dictionary() else {
        return attrs;
    };
    attrs.last_visit = d
        .get("LastVisitTime")
        .and_then(plist::Value::as_date)
        .and_then(plist_date_to_unix);
    attrs.opened_from_link = d.get("OpenedFromLink").and_then(plist::Value::as_boolean);
    attrs.showing_reader = d.get("ShowingReader").and_then(plist::Value::as_boolean);
    attrs.tab_index = d.get("TabIndex").and_then(plist::Value::as_signed_integer);
    if let Some(ss) = d.get("SessionState").and_then(plist::Value::as_data) {
        attrs.session_state_bytes = Some(ss.len());
        attrs.session_history = read_session_state(ss);
    }
    attrs
}

/// `SessionState`: a 4-byte big-endian version, then a binary plist whose
/// `SessionHistory` is the tab's back/forward list. Observed uncompressed on
/// iOS 15 (version 2); anything that does not parse as that is left undecoded
/// and the caller says so.
fn read_session_state(blob: &[u8]) -> Option<SessionHistory> {
    let body = blob.get(4..)?;
    let v = plist::Value::from_reader(Cursor::new(body)).ok()?;
    let hist = v.as_dictionary()?.get("SessionHistory")?.as_dictionary()?;
    let current_index = hist
        .get("SessionHistoryCurrentIndex")
        .and_then(plist::Value::as_signed_integer);
    let entries = hist
        .get("SessionHistoryEntries")
        .and_then(plist::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total_entries = entries.len();
    let entries = entries
        .iter()
        .take(MAX_SESSION_HISTORY_ENTRIES)
        .map(|e| {
            let mut m = Map::new();
            if let Some(d) = e.as_dictionary() {
                for (from, to) in [
                    ("SessionHistoryEntryURL", "url"),
                    ("SessionHistoryEntryOriginalURL", "original_url"),
                    ("SessionHistoryEntryTitle", "title"),
                ] {
                    if let Some(s) = d.get(from).and_then(plist::Value::as_string) {
                        if !s.is_empty() {
                            m.insert(to.into(), json!(s));
                        }
                    }
                }
            }
            Value::Object(m)
        })
        .collect();
    Some(SessionHistory {
        current_index,
        entries,
        total_entries,
    })
}

fn stamp_session_history(m: &mut Map<String, Value>, attrs: &TabAttributes) {
    match attrs.session_state_bytes {
        None => {
            m.insert("session_state_present".into(), json!(false));
        }
        Some(bytes) => {
            m.insert("session_state_present".into(), json!(true));
            m.insert("session_state_bytes".into(), json!(bytes));
            match &attrs.session_history {
                Some(h) => {
                    m.insert("session_history_decoded".into(), json!(true));
                    if let Some(i) = h.current_index {
                        m.insert("session_history_current_index".into(), json!(i));
                    }
                    m.insert("session_history_entries".into(), json!(h.total_entries));
                    m.insert("session_history".into(), Value::Array(h.entries.clone()));
                    if h.total_entries > h.entries.len() {
                        m.insert("session_history_truncated".into(), json!(true));
                        m.insert(
                            "session_history_truncated_reason".into(),
                            json!(IncompleteReason::CapReached.as_str()),
                        );
                        m.insert(
                            "session_history_cap".into(),
                            json!(MAX_SESSION_HISTORY_ENTRIES),
                        );
                    }
                }
                None => {
                    // The back/forward list is in the evidence and unread.
                    m.insert("session_history_decoded".into(), json!(false));
                    m.insert("content_incomplete".into(), json!(true));
                    m.insert(
                        "content_incomplete_reason".into(),
                        json!(IncompleteReason::UnresolvedStructure.as_str()),
                    );
                    m.insert(
                        "content_incomplete_detail".into(),
                        json!("SessionState did not parse as a versioned binary plist; the tab's back/forward history is present and unread"),
                    );
                }
            }
        }
    }
}

struct WindowRow {
    id: i64,
    uuid: Option<String>,
    private_group: Option<i64>,
    local_group: Option<i64>,
    active_group: Option<i64>,
    date_closed: Option<f64>,
}

fn safari_tabs_generation(conn: &Connection, case: Uuid, parent: Uuid) -> Vec<Artifact> {
    let mut out = Vec::new();
    if let Some(m) = schema_marker(
        conn,
        "Safari SafariTabs.db",
        &SAFARI_BOOKMARKS_SCHEMA,
        SAFARI_BOOKMARKS_EVIDENCE,
        case,
        parent,
    ) {
        out.push(m);
    }
    let (rows, mut drops) = match read_bookmark_rows(conn) {
        Ok(v) => v,
        Err(e) => {
            out.push(query_unusable_artifact(
                case,
                parent,
                "SafariTabs.db",
                "bookmarks",
                &e,
            ));
            return out;
        }
    };
    let by_id: HashMap<i64, &BookmarkRow> = rows.iter().map(|r| (r.id, r)).collect();

    // The windows and their tab groups decide which tabs are private. A tab
    // published without that answer is a tab published as not private, so a
    // windows query that does not run makes the whole store unreadable.
    let mut windows = Vec::new();
    let windows_read: rusqlite::Result<()> = (|| {
        let mut stmt = conn.prepare(
            "SELECT id, uuid, private_tab_group_id, local_tab_group_id, active_tab_group_id, date_closed \
             FROM windows ORDER BY id",
        )?;
        let iter = stmt.query_map([], |r| {
            Ok(WindowRow {
                id: cint(r, 0).unwrap_or(-1),
                uuid: cstr(r, 1),
                private_group: cint(r, 2),
                local_group: cint(r, 3),
                active_group: cint(r, 4),
                date_closed: cfloat(r, 5),
            })
        })?;
        for w in iter {
            match w {
                Ok(w) => windows.push(w),
                Err(e) => drops.record(&e),
            }
        }
        Ok(())
    })();
    if let Err(e) = windows_read {
        out.push(query_unusable_artifact(
            case,
            parent,
            "SafariTabs.db",
            "windows",
            &e,
        ));
        return out;
    }
    // tab group -> (window id, active tab id)
    let mut group_window: HashMap<i64, (i64, Option<i64>)> = HashMap::new();
    let groups_read: rusqlite::Result<()> = (|| {
        let mut stmt =
            conn.prepare("SELECT tab_group_id, window_id, active_tab_id FROM windows_tab_groups")?;
        let iter = stmt.query_map([], |r| Ok((cint(r, 0), cint(r, 1), cint(r, 2))))?;
        for row in iter.flatten() {
            if let (Some(g), Some(w)) = (row.0, row.1) {
                group_window.insert(g, (w, row.2));
            }
        }
        Ok(())
    })();
    if let Err(e) = groups_read {
        out.push(query_unusable_artifact(
            case,
            parent,
            "SafariTabs.db",
            "windows_tab_groups",
            &e,
        ));
        return out;
    }
    let private_groups: Vec<i64> = windows.iter().filter_map(|w| w.private_group).collect();
    let windows_by_id: HashMap<i64, &WindowRow> = windows.iter().map(|w| (w.id, w)).collect();

    let mut tabs = 0usize;
    let mut private_tabs = 0usize;
    let mut tab_groups = 0usize;
    let mut attribute_blob_bytes = 0i64;
    let mut local_blobs: HashMap<i64, Vec<u8>> = HashMap::new();
    if let Ok(mut stmt) =
        conn.prepare("SELECT id, local_attributes FROM bookmarks WHERE type = 0 AND local_attributes IS NOT NULL")
    {
        if let Ok(iter) = stmt.query_map([], |r| {
            Ok((cint(r, 0), r.get::<_, Vec<u8>>(1).ok()))
        }) {
            for row in iter.flatten() {
                if let (Some(id), Some(b)) = row {
                    local_blobs.insert(id, b);
                }
            }
        }
    }

    for r in &rows {
        attribute_blob_bytes += r.extra_len + r.sync_len;
        match r.kind {
            Some(1) => {
                // Folders under Root with a title are tab groups (Local,
                // Private, and any the user named); the untitled ones are the
                // pinned / recently-closed containers. Counted, not emitted.
                if r.title.is_some() && r.parent.is_some() {
                    tab_groups += 1;
                }
            }
            _ => {
                tabs += 1;
                let mut m = Map::new();
                m.insert("type".into(), json!("SafariOpenTab"));
                m.insert("subtype".into(), json!("safari_open_tab"));
                m.insert("platform".into(), json!("iOS"));
                m.insert("source".into(), json!("SafariTabs.db"));
                m.insert("source_schema".into(), json!("SafariTabs.db"));
                m.insert("tab_id".into(), json!(r.id));
                if let Some(t) = &r.title {
                    m.insert("title".into(), json!(t));
                }
                if let Some(u) = r.url.as_deref().filter(|u| !u.is_empty()) {
                    m.insert("url".into(), json!(u));
                }
                if let Some(o) = r.order_index {
                    m.insert("order_index".into(), json!(o));
                }
                if let Some(u) = &r.external_uuid {
                    m.insert("tab_uuid".into(), json!(u));
                }
                m.insert("deleted".into(), json!(r.deleted));
                let group = r.parent;
                let is_private = group.is_some_and(|g| private_groups.contains(&g));
                if is_private {
                    private_tabs += 1;
                }
                m.insert("private_browsing".into(), json!(is_private));
                if let Some(g) = group {
                    m.insert("tab_group_id".into(), json!(g));
                    if let Some(t) = by_id.get(&g).and_then(|f| f.title.clone()) {
                        m.insert("tab_group".into(), json!(t));
                    }
                    if let Some((wid, active)) = group_window.get(&g) {
                        m.insert("window_id".into(), json!(wid));
                        m.insert("is_active_tab".into(), json!(*active == Some(r.id)));
                        if let Some(w) = windows_by_id.get(wid) {
                            if let Some(u) = &w.uuid {
                                m.insert("window_uuid".into(), json!(u));
                            }
                            m.insert(
                                "tab_group_is_active".into(),
                                json!(w.active_group == Some(g)),
                            );
                        }
                    } else {
                        // A tab whose group no window claims: which window it
                        // was in, and whether it was the active tab, is not
                        // recorded here.
                        m.insert("window_unresolved".into(), json!(true));
                    }
                }
                if let Some(lm) = r.last_modified {
                    insert_cocoa(&mut m, "last_modified", lm, "bookmarks.last_modified");
                }
                if let Some(dc) = r.date_closed {
                    insert_cocoa(&mut m, "date_closed", dc, "bookmarks.date_closed");
                }
                match local_blobs.get(&r.id) {
                    Some(blob) => {
                        attribute_blob_bytes += blob.len() as i64;
                        let attrs = read_tab_attributes(blob);
                        if let Some((secs, nanos)) = attrs.last_visit {
                            m.insert("last_visit".into(), json!(secs));
                            if let Some(ns) = unix_ns(secs, nanos) {
                                m.insert("last_visit_ns".into(), json!(ns));
                            }
                            m.insert("last_visit_source".into(), json!(LAST_VISIT_SOURCE));
                            m.insert("date".into(), json!(secs));
                            if let Some(ns) = unix_ns(secs, nanos) {
                                m.insert("date_ns".into(), json!(ns));
                            }
                        }
                        if let Some(b) = attrs.opened_from_link {
                            m.insert("opened_from_link".into(), json!(b));
                        }
                        if let Some(b) = attrs.showing_reader {
                            m.insert("showing_reader".into(), json!(b));
                        }
                        if let Some(i) = attrs.tab_index {
                            m.insert("tab_index".into(), json!(i));
                        }
                        stamp_session_history(&mut m, &attrs);
                    }
                    None => {
                        m.insert("local_attributes_present".into(), json!(false));
                    }
                }
                m.insert(
                    "name".into(),
                    json!(format!(
                        "{}{}",
                        r.title
                            .clone()
                            .or_else(|| r.url.clone())
                            .unwrap_or_else(|| "Safari tab".into()),
                        if is_private { " (private)" } else { "" }
                    )),
                );
                out.push(parent_record(case, parent, Value::Object(m)));
            }
        }
    }
    let windows_n = windows.len();
    for w in &windows {
        let mut m = Map::new();
        m.insert("type".into(), json!("SafariWindow"));
        m.insert("subtype".into(), json!("safari_window"));
        m.insert("platform".into(), json!("iOS"));
        m.insert("source".into(), json!("SafariTabs.db"));
        m.insert("window_id".into(), json!(w.id));
        if let Some(u) = &w.uuid {
            m.insert("window_uuid".into(), json!(u));
        }
        for (k, v) in [
            ("local_tab_group_id", w.local_group),
            ("private_tab_group_id", w.private_group),
            ("active_tab_group_id", w.active_group),
        ] {
            if let Some(v) = v {
                m.insert(k.into(), json!(v));
            }
        }
        if let Some(dc) = w.date_closed {
            insert_cocoa(&mut m, "date_closed", dc, "windows.date_closed");
        }
        m.insert(
            "name".into(),
            json!(format!(
                "Safari window {}",
                w.uuid.as_deref().unwrap_or("(no uuid)")
            )),
        );
        out.push(parent_record(case, parent, Value::Object(m)));
    }

    let mut s = Map::new();
    s.insert("type".into(), json!("SafariTabsSummary"));
    s.insert("platform".into(), json!("iOS"));
    s.insert("source".into(), json!("SafariTabs.db"));
    s.insert("source_schema".into(), json!("SafariTabs.db"));
    s.insert("tabs".into(), json!(tabs));
    s.insert("private_tabs".into(), json!(private_tabs));
    s.insert("windows".into(), json!(windows_n));
    s.insert("tab_groups".into(), json!(tab_groups));
    s.insert("rows_dropped".into(), json!(drops.dropped()));
    s.insert(
        "attribute_blob_bytes_undecoded".into(),
        json!(attribute_blob_bytes),
    );
    if let Some(v) = user_version(conn) {
        s.insert("schema_version".into(), json!(v));
    }
    s.insert("records_recovered".into(), json!(tabs));
    if drops.dropped() > 0 {
        s.insert("inventory_incomplete".into(), json!(true));
        s.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
    }
    s.insert(
        "name".into(),
        json!(format!(
            "Safari open tabs: {tabs} tab(s), {private_tabs} private, {windows_n} window(s)"
        )),
    );
    out.push(parent_record(case, parent, Value::Object(s)));
    out
}

fn browser_state_generation(conn: &Connection, case: Uuid, parent: Uuid) -> Vec<Artifact> {
    let mut out = Vec::new();
    if let Some(m) = schema_marker(
        conn,
        "Safari BrowserState.db",
        &BROWSER_STATE_SCHEMA,
        BROWSER_STATE_EVIDENCE,
        case,
        parent,
    ) {
        out.push(m);
    }
    let mut drops = RowDrops::default();
    // Per-tab session data lives in its own table on this generation. A
    // table that is there but whose statement does not run leaves every
    // tab's session state unknown, which is said on the tab; it is not the
    // same as a tab with no session row.
    let mut session: HashMap<String, (Option<usize>, Option<i64>)> = HashMap::new();
    let session_read: Option<rusqlite::Result<()>> = has_table(conn, "tab_sessions").then(|| {
        let mut stmt = conn.prepare(
            "SELECT tab_uuid, length(session_data), uncompressed_session_data_size FROM tab_sessions",
        )?;
        let iter = stmt.query_map([], |r| Ok((cstr(r, 0), cint(r, 1), cint(r, 2))))?;
        for row in iter.flatten() {
            if let Some(u) = row.0 {
                session.insert(u, (row.1.map(|n| n as usize), row.2));
            }
        }
        Ok(())
    });
    let session_query_error: Option<String> = match &session_read {
        Some(Err(e)) => Some(e.to_string()),
        _ => None,
    };
    let mut tabs = 0usize;
    let mut private_tabs = 0usize;
    let tabs_read: rusqlite::Result<()> = (|| {
        let mut stmt = conn.prepare(
            "SELECT id, uuid, title, url, user_visible_url, order_index, last_viewed_time, \
                    private_browsing, opened_from_link, showing_reader, browser_window_uuid, \
                    browser_window_id, readinglist_bookmark_id \
             FROM tabs ORDER BY browser_window_id, order_index",
        )?;
        let iter = stmt.query_map([], |r| {
            Ok((
                cint(r, 0),
                cstr(r, 1),
                cstr(r, 2),
                cstr(r, 3),
                cstr(r, 4),
                cint(r, 5),
                cfloat(r, 6),
                cint(r, 7),
                cint(r, 8),
                cint(r, 9),
                cstr(r, 10),
                cint(r, 11),
                cint(r, 12),
            ))
        })?;
        {
            for row in iter {
                let (
                    id,
                    uuid,
                    title,
                    url,
                    visible,
                    order,
                    viewed,
                    private,
                    from_link,
                    reader,
                    wuuid,
                    wid,
                    rl,
                ) = match row {
                    Ok(r) => r,
                    Err(e) => {
                        drops.record(&e);
                        continue;
                    }
                };
                tabs += 1;
                let is_private = private.unwrap_or(0) != 0;
                if is_private {
                    private_tabs += 1;
                }
                let mut m = Map::new();
                m.insert("type".into(), json!("SafariOpenTab"));
                m.insert("subtype".into(), json!("safari_open_tab"));
                m.insert("platform".into(), json!("iOS"));
                m.insert("source".into(), json!("BrowserState.db"));
                m.insert("source_schema".into(), json!("BrowserState.db"));
                if let Some(i) = id {
                    m.insert("tab_id".into(), json!(i));
                }
                if let Some(u) = &uuid {
                    m.insert("tab_uuid".into(), json!(u));
                }
                if let Some(t) = &title {
                    m.insert("title".into(), json!(t));
                }
                if let Some(u) = url.as_deref().filter(|u| !u.is_empty()) {
                    m.insert("url".into(), json!(u));
                }
                if let Some(u) = visible.as_deref().filter(|u| !u.is_empty()) {
                    m.insert("user_visible_url".into(), json!(u));
                }
                if let Some(o) = order {
                    m.insert("order_index".into(), json!(o));
                }
                if let Some(v) = viewed {
                    insert_cocoa(&mut m, "last_visit", v, "tabs.last_viewed_time");
                    insert_cocoa(&mut m, "date", v, "tabs.last_viewed_time");
                }
                m.insert("private_browsing".into(), json!(is_private));
                if let Some(b) = from_link {
                    m.insert("opened_from_link".into(), json!(b != 0));
                }
                if let Some(b) = reader {
                    m.insert("showing_reader".into(), json!(b != 0));
                }
                if let Some(w) = &wuuid {
                    m.insert("window_uuid".into(), json!(w));
                }
                if let Some(w) = wid {
                    m.insert("window_id".into(), json!(w));
                }
                if let Some(r) = rl.filter(|r| *r != 0) {
                    m.insert("reading_list_bookmark_id".into(), json!(r));
                }
                match uuid.as_deref().and_then(|u| session.get(u)) {
                    Some((bytes, uncompressed)) => {
                        m.insert("session_state_present".into(), json!(true));
                        if let Some(b) = bytes {
                            m.insert("session_state_bytes".into(), json!(b));
                        }
                        if let Some(u) = uncompressed {
                            m.insert("session_state_uncompressed_bytes".into(), json!(u));
                        }
                        // No device held here has a row in `tab_sessions`, so
                        // its encoding has not been seen and is not decoded.
                        m.insert("session_history_decoded".into(), json!(false));
                        m.insert("content_incomplete".into(), json!(true));
                        m.insert(
                            "content_incomplete_reason".into(),
                            json!(IncompleteReason::Unvalidated.as_str()),
                        );
                        m.insert(
                            "content_incomplete_detail".into(),
                            json!("tab_sessions.session_data is present and not decoded: no BrowserState.db generation with session rows has been validated"),
                        );
                    }
                    None if session_query_error.is_some() => {
                        m.insert("session_state_unknown".into(), json!(true));
                        m.insert(
                            "session_state_unknown_reason".into(),
                            json!("tab_sessions query did not run"),
                        );
                    }
                    None => {
                        m.insert("session_state_present".into(), json!(false));
                    }
                }
                m.insert(
                    "name".into(),
                    json!(format!(
                        "{}{}",
                        title
                            .clone()
                            .or_else(|| url.clone())
                            .unwrap_or_else(|| "Safari tab".into()),
                        if is_private { " (private)" } else { "" }
                    )),
                );
                out.push(parent_record(case, parent, Value::Object(m)));
            }
        }
        Ok(())
    })();
    if let Err(e) = tabs_read {
        out.push(query_unusable_artifact(
            case,
            parent,
            "BrowserState.db",
            "tabs",
            &e,
        ));
        return out;
    }
    // A count that would not read is not zero windows (HUNT-238's class:
    // this was `table_count(..).unwrap_or(0)`).
    let windows = table_count_checked(conn, "browser_windows");
    let mut s = Map::new();
    s.insert("type".into(), json!("SafariTabsSummary"));
    s.insert("platform".into(), json!("iOS"));
    s.insert("source".into(), json!("BrowserState.db"));
    s.insert("source_schema".into(), json!("BrowserState.db"));
    s.insert("tabs".into(), json!(tabs));
    s.insert("private_tabs".into(), json!(private_tabs));
    match &windows {
        Ok(Some(n)) => {
            s.insert("windows".into(), json!(n));
        }
        Ok(None) => {
            s.insert("browser_windows_table_absent".into(), json!(true));
        }
        Err(e) => {
            s.insert("windows_count_error".into(), json!(e));
            s.insert("content_incomplete".into(), json!(true));
            s.insert(
                "content_incomplete_reason".into(),
                json!(IncompleteReason::UnresolvedStructure.as_str()),
            );
            s.insert(
                "content_incomplete_detail".into(),
                json!(format!("the window count did not complete: {e}")),
            );
        }
    }
    match &session_query_error {
        None if session_read.is_none() => {
            s.insert("tab_sessions_table_absent".into(), json!(true));
        }
        None => {
            s.insert("session_rows".into(), json!(session.len()));
        }
        Some(e) => {
            s.insert("session_rows_query_did_not_run".into(), json!(true));
            s.insert("session_rows_query_error".into(), json!(e));
        }
    }
    s.insert("rows_dropped".into(), json!(drops.dropped()));
    if let Some(v) = user_version(conn) {
        s.insert("schema_version".into(), json!(v));
    }
    s.insert("records_recovered".into(), json!(tabs));
    if tabs == 0 {
        // On iOS 15 this file is still written but its tabs moved to
        // SafariTabs.db. Zero rows here is a fact about this file, not about
        // what was open, and the summary has to say which.
        s.insert("tabs_table_empty".into(), json!(true));
        s.insert(
            "generation_note".into(),
            json!("the `tabs` table is empty; from iOS 15 open tabs are kept in SafariTabs.db, which is read separately — an empty BrowserState.db does not mean no tabs were open"),
        );
    }
    if drops.dropped() > 0 {
        s.insert("inventory_incomplete".into(), json!(true));
        s.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
    }
    s.insert(
        "name".into(),
        json!(format!(
            "Safari open tabs (BrowserState.db): {tabs} tab(s), {private_tabs} private, {}",
            match &windows {
                Ok(Some(n)) => format!("{n} window(s)"),
                Ok(None) => "windows table absent".to_string(),
                Err(_) => "windows not counted".to_string(),
            }
        )),
    );
    out.push(parent_record(case, parent, Value::Object(s)));
    out
}

// --- Recent web searches: com.apple.mobilesafari.plist -----------------------

/// Recent web searches from Safari's preferences plist.
pub struct SafariSearchesParser;

impl ForensicsModule for SafariSearchesParser {
    fn id(&self) -> &str {
        "plugin.ios.safari_searches"
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
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if basename(name) != "com.apple.mobilesafari.plist" {
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
        let declared = data.size();
        if declared > MAX_SEARCHES_PLIST_BYTES {
            return Ok(vec![searches_unreadable(
                artifact,
                name,
                IncompleteReason::CapReached,
                &format!("{declared} bytes exceeds the {MAX_SEARCHES_PLIST_BYTES}-byte ceiling"),
            )]);
        }
        let mut bytes = vec![0u8; declared as usize];
        let n = read_full(data.as_ref(), 0, &mut bytes);
        if (n as u64) < declared {
            return Ok(vec![searches_unreadable(
                artifact,
                name,
                IncompleteReason::ShortRead,
                &format!("{n} of {declared} declared bytes were delivered"),
            )]);
        }
        let Ok(v) = plist::Value::from_reader(Cursor::new(&bytes)) else {
            // Not a plist at all: not this reader's file.
            return Ok(Vec::new());
        };
        let Some(d) = v.as_dictionary() else {
            return Ok(Vec::new());
        };
        // The key selects the file. The same basename exists elsewhere
        // (CloudDocs keeps an `iCloud.com.apple.mobilesafari.plist`), and a
        // preferences file with no search history is not a search store —
        // it is left to the generic plist reader, which still renders it.
        let Some(searches) = d.get("RecentWebSearches").and_then(plist::Value::as_array) else {
            return Ok(Vec::new());
        };
        let case = artifact.case_id;
        let parent = artifact.id;
        let mut out = Vec::new();
        let mut undecodable = 0usize;
        for (i, e) in searches.iter().enumerate() {
            let Some(ed) = e.as_dictionary() else {
                undecodable += 1;
                continue;
            };
            let Some(q) = ed.get("SearchString").and_then(plist::Value::as_string) else {
                undecodable += 1;
                continue;
            };
            let mut m = Map::new();
            m.insert("type".into(), json!("WebSearchQuery"));
            m.insert("subtype".into(), json!("web_search_query"));
            m.insert("platform".into(), json!("iOS"));
            m.insert("browser".into(), json!("Safari"));
            m.insert("source".into(), json!("com.apple.mobilesafari.plist"));
            m.insert("index".into(), json!(i));
            m.insert("query".into(), json!(q));
            // The plist records the query and when; not which engine served
            // it. That is a real limit of the source, stated rather than
            // filled from the device's default-engine setting.
            m.insert("search_engine_not_recorded".into(), json!(true));
            match ed
                .get("Date")
                .and_then(plist::Value::as_date)
                .and_then(plist_date_to_unix)
            {
                Some((secs, nanos)) => {
                    m.insert("timestamp".into(), json!(secs));
                    m.insert("date".into(), json!(secs));
                    if let Some(ns) = unix_ns(secs, nanos) {
                        m.insert("timestamp_ns".into(), json!(ns));
                        m.insert("date_ns".into(), json!(ns));
                    }
                    m.insert("timestamp_source".into(), json!(SEARCH_DATE_SOURCE));
                }
                None => {
                    m.insert("timestamp_not_recorded".into(), json!(true));
                }
            }
            m.insert("name".into(), json!(format!("Safari search: {q}")));
            out.push(parent_record(case, parent, Value::Object(m)));
        }
        let mut s = Map::new();
        s.insert("type".into(), json!("SafariSearchesSummary"));
        s.insert("platform".into(), json!("iOS"));
        s.insert("source".into(), json!("com.apple.mobilesafari.plist"));
        s.insert("searches".into(), json!(out.len()));
        s.insert("entries_undecodable".into(), json!(undecodable));
        // The UDID is read from the key Safari stamps when it shows the
        // search-engine alert; the record names the key so the value is
        // sourced, not asserted.
        if let Some(u) = d
            .get("DidPromptSearchEngineAlertUDID")
            .and_then(plist::Value::as_string)
        {
            s.insert("device_udid".into(), json!(u));
            s.insert(
                "device_udid_source".into(),
                json!("DidPromptSearchEngineAlertUDID"),
            );
        }
        if let Some(dt) = d.get("SSDeviceType").and_then(plist::Value::as_dictionary) {
            if let Some(b) = dt.get("buildVersion").and_then(plist::Value::as_string) {
                s.insert("build_version".into(), json!(b));
            }
            if let Some(h) = dt.get("hardwareModel").and_then(plist::Value::as_string) {
                s.insert("hardware_model".into(), json!(h));
            }
            if let Some(n) = dt
                .get("deviceTypeNumber")
                .and_then(plist::Value::as_signed_integer)
            {
                s.insert("device_type_number".into(), json!(n));
            }
        }
        for (key, field) in [
            ("CloudTabsEnabled", "cloud_tabs_enabled"),
            ("HasExtensionsInstalled", "extensions_installed"),
        ] {
            if let Some(b) = d.get(key).and_then(plist::Value::as_boolean) {
                s.insert(field.into(), json!(b));
            }
        }
        if let Some(bc) = d
            .get("BrowserControllersSavedState")
            .and_then(plist::Value::as_dictionary)
        {
            let uuids: Vec<&str> = bc.keys().map(String::as_str).collect();
            s.insert("browser_window_uuids".into(), json!(uuids));
        }
        if let Some((secs, nanos)) = d
            .get("LastBookmarksDatabaseHealthReportDate")
            .and_then(plist::Value::as_date)
            .and_then(plist_date_to_unix)
        {
            s.insert("last_bookmarks_health_report".into(), json!(secs));
            if let Some(ns) = unix_ns(secs, nanos) {
                s.insert("last_bookmarks_health_report_ns".into(), json!(ns));
            }
            s.insert(
                "last_bookmarks_health_report_source".into(),
                json!("LastBookmarksDatabaseHealthReportDate (plist date, Apple Cocoa seconds since 2001-01-01, converted to Unix)"),
            );
        }
        if undecodable > 0 {
            s.insert("inventory_incomplete".into(), json!(true));
            s.insert(
                "inventory_incomplete_reason".into(),
                json!(IncompleteReason::UnresolvedStructure.as_str()),
            );
        }
        s.insert(
            "name".into(),
            json!(format!("Safari recent searches: {} search(es)", out.len())),
        );
        out.push(parent_record(case, parent, Value::Object(s)));
        Ok(out)
    }
}

fn searches_unreadable(
    artifact: &Artifact,
    name: &str,
    reason: IncompleteReason,
    detail: &str,
) -> Artifact {
    let mut m = Map::new();
    m.insert("type".into(), json!("IosArtifactParseStatus"));
    m.insert("subtype".into(), json!("parse_incomplete"));
    m.insert("status".into(), json!("PlistUnreadable"));
    m.insert("file_name".into(), json!(name));
    m.insert("content_incomplete".into(), json!(true));
    m.insert("content_incomplete_reason".into(), json!(reason.as_str()));
    m.insert("inventory_incomplete".into(), json!(true));
    m.insert("inventory_incomplete_reason".into(), json!(reason.as_str()));
    m.insert("records_recovered".into(), json!(0));
    m.insert("detail".into(), json!(detail));
    m.insert(
        "name".into(),
        json!(format!("{name}: Safari preferences unreadable — {detail}")),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(artifact.id)
    .with_subtype("parse_incomplete")
}
