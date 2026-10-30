#![forbid(unsafe_code)]
#[cfg(test)]
mod schema_golden_tests;
mod schema_support;
#[cfg(test)]
mod tests;
mod walk;

use anyhow::{Context, Result};
use rusqlite::Connection;
use schema_support::{
    assess_version, keyed_version, plan_columns, unresolved_fields_marker, user_version,
    ColumnPlan, SchemaSupport, SchemaVersion,
};
use seance_core::io::{read_capped, IncompleteReason};
use seance_core::time::{
    cocoa_secs_to_unix_nanos, prtime_to_unix_secs, webkit_us_to_unix_secs, webkit_us_to_unix_us,
};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{cap_marker, CapCounter, RowDrops};
use seance_sqlite_util::{probe_table, Presence};
use seance_sqlite_util::{SupportedRange, TempDb};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;
use walk::{walk_capped_rows, CappedWalk};

// --- Schema-drift defence (ROADMAP §1.4a) ------------------------------------
//
// Every range below was read out of real browser stores on the machine that
// wrote this code; each `evidence` string names them. Chromium keeps its
// version in the `meta` table (`PRAGMA user_version` is 0 on every real
// Chromium store), Firefox and Safari in `PRAGMA user_version`. A store outside
// its range is still parsed and a `ParserStaleWarning` is appended; a store
// whose required columns did not resolve has that walk skipped and the fields
// named on the marker, and the other walks still run.

/// Chrome/Edge `History`: meta.version 20 (plaso `chrome_history/History`),
/// 32, 33, 36 (plaso `History-57/58/59.*`), 41 (chromebook), 51 (android2022),
/// 70 (a current desktop Chrome profile).
const CHROME_HISTORY_SUPPORT: SchemaSupport = SchemaSupport {
    app: "chrome-history",
    store: "History",
    record_type: "BrowserHistory",
    range: SupportedRange {
        min: 20,
        max: Some(70),
    },
    evidence: "meta.version 20/32/33/36 (reference/plaso/test_data/chrome_history), 41 \
               (chromebook Default/History), 51 (android2022 com.android.chrome), 70 \
               (desktop Chrome, 2026)",
};

/// Chrome/Edge `Cookies`: meta.version 5 (plaso `cookies.db`), 10 (plaso
/// `Cookies-68.0.3440.106`), 11 (chromebook), 16 (android2022), 24 (desktop).
const CHROME_COOKIES_SUPPORT: SchemaSupport = SchemaSupport {
    app: "chrome-cookies",
    store: "Cookies",
    record_type: "BrowserCookie",
    range: SupportedRange {
        min: 5,
        max: Some(24),
    },
    evidence: "meta.version 5 (reference/plaso/test_data/cookies.db), 10 (plaso \
               Cookies-68.0.3440.106), 11 (chromebook user/Cookies), 16 (android2022 \
               com.android.chrome), 24 (desktop Chrome, 2026)",
};

/// Chrome/Edge `Web Data`: meta.version 77 (plaso), 81 (chromebook), 98
/// (android2022), 152 (desktop).
const CHROME_WEBDATA_SUPPORT: SchemaSupport = SchemaSupport {
    app: "chrome-webdata",
    store: "Web Data",
    record_type: "BrowserAutofill",
    range: SupportedRange {
        min: 77,
        max: Some(152),
    },
    evidence: "meta.version 77 (reference/plaso/test_data/Web Data), 81 (chromebook), 98 \
               (android2022 com.android.chrome), 152 (desktop Chrome, 2026)",
};

/// Chrome/Edge `Login Data`: meta.version 24 (chromebook), 31 (android2022),
/// 43 (desktop).
const CHROME_LOGINS_SUPPORT: SchemaSupport = SchemaSupport {
    app: "chrome-logins",
    store: "Login Data",
    record_type: "BrowserLogin",
    range: SupportedRange {
        min: 24,
        max: Some(43),
    },
    evidence: "meta.version 24 (chromebook user/Login Data), 31 (android2022 \
               com.android.chrome), 43 (desktop Chrome, 2026)",
};

/// Firefox `places.sqlite`: user_version 10 and 23 (plaso `firefox_history/`),
/// 75 (plaso `places118.sqlite`), 82 (a current Firefox profile).
const FIREFOX_PLACES_SUPPORT: SchemaSupport = SchemaSupport {
    app: "firefox-places",
    store: "places.sqlite",
    record_type: "BrowserHistory",
    range: SupportedRange {
        min: 10,
        max: Some(82),
    },
    evidence: "PRAGMA user_version 10, 23 (reference/plaso/test_data/firefox_history), 75 \
               (plaso places118.sqlite), 82 (Firefox, 2026)",
};

/// Firefox `cookies.sqlite`: user_version 5 and 12 (plaso `firefox_cookies/`),
/// 16 (a current Firefox profile).
const FIREFOX_COOKIES_SUPPORT: SchemaSupport = SchemaSupport {
    app: "firefox-cookies",
    store: "cookies.sqlite",
    record_type: "BrowserCookie",
    range: SupportedRange {
        min: 5,
        max: Some(16),
    },
    evidence: "PRAGMA user_version 5, 12 (reference/plaso/test_data/firefox_cookies), 16 \
               (Firefox, 2026)",
};

/// Firefox `formhistory.sqlite`: user_version 5, the one real store seen (a
/// current Firefox profile); no reference corpus here holds another.
const FIREFOX_FORMHISTORY_SUPPORT: SchemaSupport = SchemaSupport {
    app: "firefox-formhistory",
    store: "formhistory.sqlite",
    record_type: "BrowserAutofill",
    range: SupportedRange {
        min: 5,
        max: Some(5),
    },
    evidence: "PRAGMA user_version 5 (Firefox, 2026)",
};

/// Safari `History.db`: user_version 13 (plaso), 15 (macos2021), 16
/// (ios2022ffs).
const SAFARI_HISTORY_SUPPORT: SchemaSupport = SchemaSupport {
    app: "safari-history",
    store: "History.db",
    record_type: "BrowserHistory",
    range: SupportedRange {
        min: 13,
        max: Some(16),
    },
    evidence: "PRAGMA user_version 13 (reference/plaso/test_data/History.db), 15 (macos2021 \
               Users/eliflatt/Library/Safari/History.db), 16 (ios2022ffs \
               /private/var/mobile/Library/Safari/History.db)",
};

/// The columns each walk reads, as (logical name, candidate columns). A field
/// listed as required is one the walk is meaningless without; when no candidate
/// resolves it, the walk is skipped and the field named on the marker. Optional
/// fields are ones an older real store genuinely lacks, read as NULL there.
const CHROME_URLS: &[(&str, &[&str])] = &[
    ("id", &["id"]),
    ("url", &["url"]),
    ("title", &["title"]),
    ("visit_count", &["visit_count"]),
    ("last_visit_time", &["last_visit_time"]),
];
const CHROME_VISITS: &[(&str, &[&str])] = &[
    ("url", &["url"]),
    ("visit_time", &["visit_time"]),
    ("transition", &["transition"]),
];
/// `full_path` is meta.version 20's name for the target (the plaso reference).
const CHROME_DOWNLOADS: &[(&str, &[&str])] = &[
    ("target_path", &["target_path", "full_path"]),
    ("start_time", &["start_time"]),
    ("total_bytes", &["total_bytes"]),
];
/// `url` is meta.version 20's own download URL, before url chains existed;
/// the rest arrived with later schemas.
const CHROME_DOWNLOADS_OPTIONAL: &[(&str, &[&str])] = &[
    ("tab_url", &["tab_url"]),
    ("end_time", &["end_time"]),
    ("danger_type", &["danger_type"]),
    ("opened", &["opened"]),
    ("url", &["url"]),
];
const CHROME_URL_CHAINS: &[(&str, &[&str])] = &[
    ("id", &["id"]),
    ("chain_index", &["chain_index"]),
    ("url", &["url"]),
];
/// `secure` / `httponly` are meta.version 5's names (the plaso reference).
const CHROME_COOKIES: &[(&str, &[&str])] = &[
    ("host_key", &["host_key"]),
    ("name", &["name"]),
    ("value", &["value"]),
    ("path", &["path"]),
    ("creation_utc", &["creation_utc"]),
    ("expires_utc", &["expires_utc"]),
    ("last_access_utc", &["last_access_utc"]),
    ("is_secure", &["is_secure", "secure"]),
    ("is_httponly", &["is_httponly", "httponly"]),
];
/// Absent at meta.version 5, before Chromium encrypted cookie values.
const CHROME_COOKIES_OPTIONAL: &[(&str, &[&str])] = &[("encrypted_value", &["encrypted_value"])];
const CHROME_AUTOFILL: &[(&str, &[&str])] = &[
    ("name", &["name"]),
    ("value", &["value"]),
    ("count", &["count"]),
    ("date_created", &["date_created"]),
    ("date_last_used", &["date_last_used"]),
];
const CHROME_LOGINS: &[(&str, &[&str])] = &[
    ("origin_url", &["origin_url"]),
    ("username_value", &["username_value"]),
    ("password_value", &["password_value"]),
    ("date_created", &["date_created"]),
    ("times_used", &["times_used"]),
];
/// Absent at meta.version 24 (the chromebook store).
const CHROME_LOGINS_OPTIONAL: &[(&str, &[&str])] = &[("date_last_used", &["date_last_used"])];
const FIREFOX_PLACES: &[(&str, &[&str])] = &[
    ("id", &["id"]),
    ("url", &["url"]),
    ("title", &["title"]),
    ("visit_count", &["visit_count"]),
    ("last_visit_date", &["last_visit_date"]),
];
const FIREFOX_VISITS: &[(&str, &[&str])] = &[
    ("place_id", &["place_id"]),
    ("visit_date", &["visit_date"]),
    ("visit_type", &["visit_type"]),
];
const FIREFOX_BOOKMARKS: &[(&str, &[&str])] = &[
    ("title", &["title"]),
    ("fk", &["fk"]),
    ("type", &["type"]),
    ("dateAdded", &["dateAdded"]),
    ("lastModified", &["lastModified"]),
];
const FIREFOX_COOKIES: &[(&str, &[&str])] = &[
    ("host", &["host"]),
    ("name", &["name"]),
    ("value", &["value"]),
    ("path", &["path"]),
    ("expiry", &["expiry"]),
    ("creationTime", &["creationTime"]),
    ("lastAccessed", &["lastAccessed"]),
    ("isSecure", &["isSecure"]),
    ("isHttpOnly", &["isHttpOnly"]),
];
const FIREFOX_FORMHISTORY: &[(&str, &[&str])] = &[
    ("fieldname", &["fieldname"]),
    ("value", &["value"]),
    ("timesUsed", &["timesUsed"]),
    ("firstUsed", &["firstUsed"]),
    ("lastUsed", &["lastUsed"]),
];
const SAFARI_ITEMS: &[(&str, &[&str])] = &[
    ("id", &["id"]),
    ("url", &["url"]),
    ("visit_count", &["visit_count"]),
];
const SAFARI_VISITS: &[(&str, &[&str])] = &[
    ("history_item", &["history_item"]),
    ("visit_time", &["visit_time"]),
    ("title", &["title"]),
];

/// Resolve one table's columns. `Ok(None)` means a required field had no
/// candidate: the marker naming it has been pushed to `out` and the caller
/// skips the walk. `Err` means the column list itself would not read, which is
/// the same failure as an unreadable catalogue and takes the same path.
#[allow(clippy::too_many_arguments)]
fn resolved_plan(
    conn: &Connection,
    support: &SchemaSupport,
    table: &str,
    required: &[(&str, &[&str])],
    optional: &[(&str, &[&str])],
    out: &mut Vec<Artifact>,
    case_id: Uuid,
    parent_id: Uuid,
) -> Result<Option<ColumnPlan>> {
    let plan = plan_columns(conn, table, required, optional)
        .map_err(|why| anyhow::anyhow!("Failed to read the `{table}` columns: {why}"))?;
    if plan.missing_required().is_empty() {
        Ok(Some(plan))
    } else {
        out.push(unresolved_fields_marker(
            support, table, &plan, 0, case_id, parent_id,
        ));
        Ok(None)
    }
}

/// The physical column for a required field of a plan [`resolved_plan`]
/// accepted, so it is always present.
fn col<'a>(plan: &'a ColumnPlan, logical: &str) -> &'a str {
    plan.column(logical)
        .expect("a required field of an accepted plan resolved")
}

/// The SELECT expression for an optional field: `alias.column` when it
/// resolved, `NULL` when the store predates it. The substitution is never
/// silent — the field is declared optional because a named real store lacks
/// it, and the row reader omits rather than invents the value.
fn opt(plan: &ColumnPlan, logical: &str, alias: &str) -> String {
    match plan.column(logical) {
        Some(c) if alias.is_empty() => c.to_string(),
        Some(c) => format!("{alias}.{c}"),
        None => "NULL".to_string(),
    }
}

/// Which validated schema a (browser, kind) pair is checked against.
fn support_for(browser: &str, kind: DbKind) -> Option<&'static SchemaSupport> {
    match (browser, kind) {
        ("Chrome/Edge", DbKind::History) => Some(&CHROME_HISTORY_SUPPORT),
        ("Chrome/Edge", DbKind::Cookies) => Some(&CHROME_COOKIES_SUPPORT),
        ("Chrome/Edge", DbKind::Autofill) => Some(&CHROME_WEBDATA_SUPPORT),
        ("Chrome/Edge", DbKind::Logins) => Some(&CHROME_LOGINS_SUPPORT),
        ("Firefox", DbKind::History) => Some(&FIREFOX_PLACES_SUPPORT),
        ("Firefox", DbKind::Cookies) => Some(&FIREFOX_COOKIES_SUPPORT),
        ("Firefox", DbKind::Autofill) => Some(&FIREFOX_FORMHISTORY_SUPPORT),
        ("Safari", DbKind::History) => Some(&SAFARI_HISTORY_SUPPORT),
        _ => None,
    }
}

/// The marker a store's schema version owes, or `None` when it is inside the
/// validated range.
///
/// Chromium stores also publish `last_compatible_version`: their own statement
/// that a reader written for anything older cannot read the file. When it is
/// past what this parser was validated to, that is the strongest signal there
/// is and the marker carries it — and it is the one out-of-range case that
/// claims incompleteness (`content_incomplete`, reason `unvalidated`). Any
/// other version outside the range is a disclosure only (ROADMAP §1.4a,
/// decided 2026-09-26).
fn version_marker(
    conn: &Connection,
    browser: &str,
    support: &SchemaSupport,
    case_id: Uuid,
    parent_id: Uuid,
) -> Option<Artifact> {
    let version = if browser == "Chrome/Edge" {
        keyed_version(conn, "meta", "key", "value", "version")
    } else {
        user_version(conn)
    };
    let mut marker = assess_version(support, &version, case_id, parent_id)?;
    if browser == "Chrome/Edge" && matches!(version, SchemaVersion::Found(_)) {
        if let SchemaVersion::Found(floor) =
            keyed_version(conn, "meta", "key", "value", "last_compatible_version")
        {
            marker.metadata["chromium_last_compatible_version"] = json!(floor);
            if support.range.max.is_some_and(|max| floor > max) {
                let sentence = format!(
                    " Chromium states (meta.last_compatible_version {floor}) that a reader \
                     written for any schema older than {floor} cannot read this store, and this \
                     parser was validated up to {}.",
                    support.range.describe()
                );
                let message = format!(
                    "{}{sentence}",
                    marker.metadata["message"].as_str().unwrap_or_default()
                );
                marker.metadata["message"] = json!(message);
                marker.metadata["detail"] = json!(message);
                marker.metadata["content_incomplete"] = json!(true);
                marker.metadata["content_incomplete_reason"] =
                    json!(IncompleteReason::Unvalidated.as_str());
                marker.metadata["content_incomplete_detail"] = json!(message);
            }
        }
    }
    Some(marker)
}

/// Maximum number of rows any one browser-database walk will extract, to bound
/// memory on a hostile or simply enormous profile.
///
/// Every walk that binds this also binds one probe row past it (see
/// [`seance_sqlite_util::CapCounter`]) and emits a `parse_incomplete` marker
/// when that row appears.
/// A bare `LIMIT` here would make "this profile held exactly 100,000 visits"
/// and "we stopped reading after 100,000" the same answer, and the walks are
/// newest-first — so what a wrong answer would look like is an examiner
/// concluding a site was never visited from a listing whose older half was
/// silently dropped.
///
/// Every capped walk in this file must also order on something beyond its
/// timestamp. Ordering on `visit_time` / `dateAdded` / `start_time` alone leaves
/// rows that share a timestamp in whatever order SQLite's sorter happened to
/// produce, so which of them survives the cap is undefined and two runs over the
/// same evidence can disagree about which rows exist. Each walk therefore breaks
/// ties on the identity columns it already selects (URL first, since `urls.url`
/// and `moz_places.url` are unique, so the URL fixes the rest of the row). An
/// examiner has to be able to re-run the tool and get the same listing.
const MAX_HISTORY_ENTRIES: usize = 100_000;

/// Row budget for the Firefox bookmark inventory. Smaller than the history cap
/// because bookmarks are a hand-curated list; it is flagged the same way.
const MAX_BOOKMARK_ENTRIES: usize = 10_000;

/// Maximum on-disk database size we will spill and open.
const MAX_DB_BYTES: u64 = 500 * 1024 * 1024;

/// Maximum on-disk size of a Firefox session-restore container we will read.
const MAX_SESSION_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum decompressed size we will expand a session container to (the header
/// declares this, so an inflated figure is a decompression-bomb vector).
const MAX_SESSION_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;

/// Maximum on-disk size of a Chrome/Edge `Preferences` file we will read.
const MAX_PREFS_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum on-disk size of a Safari `Cookies.binarycookies` jar we will read.
/// Real jars are small (the reference sample at
/// `reference/plaso/test_data/Cookies.binarycookies` is 12 KB for dozens of
/// cookies), but the ceiling is set at the same 256 MB as the Firefox session
/// container above rather than lower, for the same reason: `read_whole` holds
/// the entire file in memory, so this is also the memory cost of a hostile or
/// merely enormous jar.
const MAX_BINARYCOOKIES_BYTES: u64 = 256 * 1024 * 1024;

/// Length, in bytes, of a binarycookies page header before its offsets array:
/// a 4-byte page signature plus a 4-byte little-endian record count. See
/// [`parse_binarycookies_page_header`].
const BC_PAGE_HEADER_LEN: usize = 8;

/// Length, in bytes, of the all-zero field between a binarycookies page's
/// offsets array and its first record. See [`parse_binarycookies_page_header`].
const BC_END_OF_PAGE_MARKER_LEN: usize = 4;

/// Length, in bytes, of a binarycookies record's fixed header (four u32 pairs,
/// one u64, two f64 — `4*8 + 8 + 8 + 8`) before its NUL-terminated strings. See
/// [`parse_binarycookies_record`].
const BC_RECORD_HEADER_LEN: usize = 56;

/// Bit 0 of a binarycookies record's `flags` field: the cookie is Secure.
/// Confirmed against the reference jar at
/// `reference/plaso/test_data/Cookies.binarycookies`, whose `flags` values are
/// exactly `{0, 1, 4, 5}` — the plaso/dtFabric definition this module also
/// follows (`reference/plaso/plaso/parsers/safari_cookies.yaml`) leaves the
/// bits unnamed, so this repository has no vendored spec to cite instead.
const SAFARI_COOKIE_FLAG_SECURE: u32 = 0x1;

/// Bit 2 of a binarycookies record's `flags` field: the cookie is HttpOnly.
/// See [`SAFARI_COOKIE_FLAG_SECURE`] for how this is confirmed.
const SAFARI_COOKIE_FLAG_HTTPONLY: u32 = 0x4;

/// A non-SQLite browser file whose bytes could not all be obtained.
struct ShortFile {
    reason: IncompleteReason,
    /// Bytes the source said the file has.
    declared: u64,
    /// Bytes actually obtained (0 when the file was refused outright).
    read: u64,
}

/// Read a whole non-SQLite browser file, or say why the whole file is not here.
///
/// The SQLite path gets this for free: [`TempDb::spill`] compares what the
/// source delivered against what it declared, and `TempDb::stamp_incompleteness`
/// carries the answer onto every record. The two JSON-shaped browser files — the
/// Firefox session store and the Chrome/Edge `Preferences` — never go through a
/// spill, so nothing here ever compared the read length against
/// `DataSource::size()`. Over the byte ceiling, or short of the declared size,
/// both simply returned an EMPTY artifact list, which made "this profile had no
/// open tabs / no extensions installed" and "we could not read this file" the
/// same answer to an examiner.
fn read_whole(ds: &dyn DataSource, max_bytes: u64) -> std::result::Result<Vec<u8>, ShortFile> {
    let declared = ds.size();
    if declared > max_bytes {
        return Err(ShortFile {
            reason: IncompleteReason::CapReached,
            declared,
            read: 0,
        });
    }
    let bytes = read_capped(ds, max_bytes);
    if (bytes.len() as u64) < declared {
        return Err(ShortFile {
            reason: IncompleteReason::ShortRead,
            declared,
            read: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

/// The record that says a non-SQLite browser file was not read in full, so the
/// records around it are a subset of what the file holds — or, when nothing was
/// readable at all, that the absence of records is not an absence of activity.
///
/// `record_type` must not be the `type` the walk's own records carry, for the
/// same reason [`seance_sqlite_util::cap_marker`] documents: `seance_db` groups
/// ParsedRecords by `metadata.$.type`, so reusing it would file this marker as a
/// browsing record.
fn file_incomplete_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    file_name: &str,
    short: &ShortFile,
    detail: &str,
) -> Artifact {
    let mut meta = incomplete_meta(
        record_type,
        "FileNotReadInFull",
        file_name,
        short.reason,
        detail,
    );
    meta.insert("declared_bytes".into(), json!(short.declared));
    meta.insert("bytes_read".into(), json!(short.read));
    marker_artifact(case_id, parent_id, meta)
}

/// The record that says a browser file was never read AT ALL, because no data
/// source was attached to it.
///
/// The SQLite branch of `BrowserHistoryParser::process` has always emitted an
/// identification record for this case. The two non-SQLite branches returned an
/// empty list, which the orchestrator logs as a completed run that produced zero
/// records — so a session store or a `Preferences` file nobody could read was
/// reported exactly like a profile with no open tabs and no extensions. No byte
/// count is emitted here on purpose: with no source there is nothing to ask for
/// the size, and a `0` would read as "the file was empty".
fn unread_file_marker(
    case_id: Uuid,
    parent_id: Uuid,
    record_type: &str,
    file_name: &str,
    detail: &str,
) -> Artifact {
    let meta = incomplete_meta(
        record_type,
        "FileNotRead",
        file_name,
        IncompleteReason::UnresolvedStructure,
        detail,
    );
    marker_artifact(case_id, parent_id, meta)
}

/// The metadata every incompleteness marker in this crate carries. Both flags
/// are set together because both statements are true of these files: the BYTES
/// are short (`content_incomplete`) and so is the LIST of records built from
/// them (`inventory_incomplete`) — nothing in the part we never held was
/// enumerated.
///
/// `detail` is stamped on `<flag>_detail` as well as on the bare `detail`,
/// because the examiner-facing reader (`frontend/src/lib/incompleteness.ts`)
/// takes the parser's sentence from `content_incomplete_detail` /
/// `inventory_incomplete_detail` and reads nothing named `detail`. Without them
/// the examiner met the machine token — "short_read" — and never the sentence
/// saying which file it was or how many of its bytes are missing.
fn incomplete_meta(
    record_type: &str,
    status: &str,
    file_name: &str,
    reason: IncompleteReason,
    detail: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let reason = reason.as_str();
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!(record_type));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!(status));
    meta.insert("file_name".into(), json!(file_name));
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert("content_incomplete_reason".into(), json!(reason));
    meta.insert("inventory_incomplete".into(), json!(true));
    meta.insert("inventory_incomplete_reason".into(), json!(reason));
    meta.insert("content_incomplete_detail".into(), json!(detail));
    meta.insert("inventory_incomplete_detail".into(), json!(detail));
    meta.insert("detail".into(), json!(detail));
    meta.insert(
        "name".into(),
        json!(format!("{file_name}: incomplete — {detail}")),
    );
    meta
}

/// Wrap marker metadata as the ParsedRecord an examiner sees.
fn marker_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    meta: serde_json::Map<String, serde_json::Value>,
) -> Artifact {
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

/// Does `table` exist in this database?
///
/// The probe used to be `query_row(..).unwrap_or(false)` at fourteen sites, so a
/// database SQLite could not read at all — a carved fragment, a file whose first
/// page was overwritten, anything answering `SQLITE_NOTADB` — reported "the
/// table is not there" and the walk returned an empty artifact list with a
/// `warn!`. The orchestrator then logged a COMPLETED run producing zero records,
/// which is what an examiner reads as "this browser held no history". A read
/// that could not be performed and a table that genuinely is not present must
/// not give the same answer, so this fails closed: the error reaches
/// `BrowserHistoryParser::process`, which emits the `ParseFailed` record.
fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    // Delegates so views count as present; see the note in the `bool` form of
    // this helper elsewhere in the tree. `Undetermined` stays an error here,
    // because a catalogue that would not read is not an absent table.
    match probe_table(conn, table) {
        Presence::Present => Ok(true),
        Presence::Absent => Ok(false),
        Presence::Undetermined(why) => Err(anyhow::anyhow!(
            "Failed to read the schema catalogue looking for '{table}': {why}"
        )),
    }
}

pub struct BrowserHistoryParser;

/// Identifies which browser a history file belongs to based on its name.
fn identify_browser(name: &str) -> Option<&'static str> {
    match name {
        "History" => Some("Chrome/Edge"),
        "places.sqlite" => Some("Firefox"),
        "History.db" => Some("Safari"),
        _ => None,
    }
}

/// Identifies which browser a cookie database belongs to based on its name.
/// (Safari's own cookie jar, `Cookies.binarycookies`, is Apple's own binary
/// format — magic `cook`, not a SQLite database and not a property list — and
/// is identified separately by [`is_safari_binarycookies`] and handled by
/// [`parse_safari_binarycookies`] before the SQLite path below is reached.)
fn identify_cookies(name: &str) -> Option<&'static str> {
    match name {
        "Cookies" => Some("Chrome/Edge"),
        "cookies.sqlite" => Some("Firefox"),
        _ => None,
    }
}

/// Identifies which browser an autofill / form-history database belongs to.
fn identify_autofill(name: &str) -> Option<&'static str> {
    match name {
        "Web Data" => Some("Chrome/Edge"),
        "formhistory.sqlite" => Some("Firefox"),
        _ => None,
    }
}

/// Identifies a Chrome/Edge saved-logins database. (Firefox stores logins in an
/// NSS-encrypted `logins.json`, not SQLite, so it is not covered here.)
fn identify_logins(name: &str) -> Option<&'static str> {
    match name {
        "Login Data" => Some("Chrome/Edge"),
        _ => None,
    }
}

/// Identifies a Firefox session-restore file (LZ4-compressed JSON, not SQLite).
fn is_firefox_session(name: &str) -> bool {
    matches!(
        name,
        "sessionstore.jsonlz4" | "recovery.jsonlz4" | "previous.jsonlz4"
    )
}

/// Identifies a Chrome/Edge profile preferences file. These carry the installed
/// extension inventory (JSON, not SQLite); the content is verified before use so
/// an unrelated file named "Preferences" is never mistaken for a profile.
fn is_browser_preferences(name: &str) -> bool {
    matches!(name, "Preferences" | "Secure Preferences")
}

/// Identifies Safari's own cookie jar. Distinct from every other file this
/// crate reads by name: it is neither of the two SQLite jars [`identify_cookies`]
/// matches, nor a JSON container like the Firefox session store or the Chrome
/// `Preferences` file above — it is Apple's own binary format, read by
/// [`parse_safari_binarycookies`].
fn is_safari_binarycookies(name: &str) -> bool {
    name == "Cookies.binarycookies"
}

/// Which kind of browser database is being parsed.
#[derive(Clone, Copy)]
enum DbKind {
    History,
    Cookies,
    Autofill,
    Logins,
}

impl DbKind {
    fn label(self) -> &'static str {
        match self {
            DbKind::History => "history",
            DbKind::Cookies => "cookies",
            DbKind::Autofill => "autofill",
            DbKind::Logins => "logins",
        }
    }
}

/// Parse Chrome/Edge History database.
///
/// Schema: `urls` table has (id, url, title, visit_count, last_visit_time),
/// `visits` table has (id, url, visit_time, from_visit, transition).
/// Timestamps are WebKit epoch (microseconds since 1601-01-01).
///
/// Every column is resolved through a [`ColumnPlan`] before a query is written:
/// a `SELECT` naming a column the profile renamed fails whole, and the profile
/// would then read as unparseable when only a column moved. A table whose
/// required columns did not resolve is skipped and declared by field, and the
/// walks that did resolve still run.
///
/// Rows this crate fetched and could not decode are counted and declared by
/// [`seance_sqlite_util::RowDrops`], which [`walk_capped_rows`] owns. This file
/// used to carry a private copy of it, and the copy had fallen behind: it
/// stamped a bare `detail` key, so the sentence naming the table, the count and
/// the decoder's reason never reached the examiner-facing reader (which keys off
/// `content_incomplete_detail` / `inventory_incomplete_detail`) and they were
/// shown the token "unresolved structure" alone.
///
/// `max_entries` bounds each of the three walks (visits, urls, downloads)
/// independently. Any walk that hits its bound appends a `parse_incomplete`
/// marker, so the examiner learns that the oldest visits or downloads were not
/// extracted rather than reading the listing as the whole browsing history.
fn parse_chrome(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();

    // Check if required tables exist
    let has_urls = table_exists(conn, "urls")?;
    let has_visits = table_exists(conn, "visits")?;

    if !has_urls {
        warn!("Chrome History DB missing 'urls' table");
        return Ok(artifacts);
    }
    let Some(urls) = resolved_plan(
        conn,
        &CHROME_HISTORY_SUPPORT,
        "urls",
        CHROME_URLS,
        &[],
        &mut artifacts,
        case_id,
        parent_id,
    )?
    else {
        // Nothing keyed on `urls` can be read; downloads still can.
        parse_chrome_downloads(conn, case_id, parent_id, max_entries, &mut artifacts)?;
        return Ok(artifacts);
    };
    let visits = if has_visits {
        resolved_plan(
            conn,
            &CHROME_HISTORY_SUPPORT,
            "visits",
            CHROME_VISITS,
            &[],
            &mut artifacts,
            case_id,
            parent_id,
        )?
    } else {
        None
    };

    if let Some(visits) = visits {
        // Join urls and visits for full history with individual visit timestamps
        let sql = format!(
            "SELECT u.{url}, u.{title}, v.{visit_time}, u.{visit_count}, v.{transition}
             FROM visits v
             JOIN urls u ON v.{visit_url} = u.{id}
             ORDER BY v.{visit_time} DESC, u.{url} ASC, v.{transition} ASC
             LIMIT ?1",
            url = col(&urls, "url"),
            title = col(&urls, "title"),
            visit_count = col(&urls, "visit_count"),
            id = col(&urls, "id"),
            visit_url = col(&visits, "url"),
            visit_time = col(&visits, "visit_time"),
            transition = col(&visits, "transition"),
        );
        let walk = CappedWalk {
            sql: &sql,
            source_table: "visits",
            marker_type: "BrowserHistoryIncomplete",
            what: "Chrome visits",
            max_entries,
        };
        artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
            let url = row.get::<_, String>(0)?;
            let title = row.get::<_, Option<String>>(1)?;
            let visit_time_webkit = row.get::<_, i64>(2)?;
            let visit_count = row.get::<_, i64>(3)?;
            let transition = row.get::<_, i64>(4)?;

            // Convert WebKit timestamp (microseconds since 1601-01-01) to
            // Unix epoch; null when unset, full microsecond precision in _us
            let title_str = title.unwrap_or_default();
            let visit_time = webkit_us_to_unix_secs(visit_time_webkit);
            let mut out = Vec::new();
            if let Some(ts) = visit_time {
                out.push(make_visit_timeline_event(
                    case_id,
                    parent_id,
                    "Chrome/Edge",
                    &url,
                    &title_str,
                    ts,
                ));
            }
            let metadata = json!({
                "type": "BrowserHistory",
                "subtype": "browser_visit",
                "browser": "Chrome/Edge",
                "url": url,
                "title": title_str,
                "visit_time": visit_time,
                "visit_time_us": webkit_us_to_unix_us(visit_time_webkit),
                "visit_count": visit_count,
                "transition_type": chrome_transition_name(transition),
                "name": format!("Visit: {}", truncate_url(&url, 80)),
            });
            out.push(
                Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(parent_id)
                    .with_subtype("browser_visit"),
            );
            Ok(out)
        })?);
    } else {
        // Fallback: just parse urls table without visit details. Taken both
        // when there is no `visits` table and when its columns did not resolve
        // (declared above), so the profile is listed either way.
        let sql = format!(
            "SELECT {url}, {title}, {visit_count}, {last_visit_time} FROM urls \
             ORDER BY {last_visit_time} DESC, {url} ASC LIMIT ?1",
            url = col(&urls, "url"),
            title = col(&urls, "title"),
            visit_count = col(&urls, "visit_count"),
            last_visit_time = col(&urls, "last_visit_time"),
        );
        let walk = CappedWalk {
            sql: &sql,
            source_table: "urls",
            marker_type: "BrowserHistoryIncomplete",
            what: "Chrome urls",
            max_entries,
        };
        artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
            let url = row.get::<_, String>(0)?;
            let title = row.get::<_, Option<String>>(1)?;
            let visit_count = row.get::<_, i64>(2)?;
            let last_visit_time = row.get::<_, i64>(3)?;

            let title_str = title.unwrap_or_default();
            let visit_time = webkit_us_to_unix_secs(last_visit_time);
            let mut out = Vec::new();
            if let Some(ts) = visit_time {
                out.push(make_visit_timeline_event(
                    case_id,
                    parent_id,
                    "Chrome/Edge",
                    &url,
                    &title_str,
                    ts,
                ));
            }
            let metadata = json!({
                "type": "BrowserHistory",
                "subtype": "browser_visit",
                "browser": "Chrome/Edge",
                "url": url,
                "title": title_str,
                "visit_time": visit_time,
                "visit_time_us": webkit_us_to_unix_us(last_visit_time),
                "visit_count": visit_count,
                "name": format!("Visit: {}", truncate_url(&url, 80)),
            });
            out.push(
                Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(parent_id)
                    .with_subtype("browser_visit"),
            );
            Ok(out)
        })?);
    }

    parse_chrome_downloads(conn, case_id, parent_id, max_entries, &mut artifacts)?;
    Ok(artifacts)
}

/// The Chrome `downloads` walk, appended to `artifacts` when the table is
/// present and its required columns resolve.
///
/// The URL the bytes actually came from lives in `downloads_url_chains` (one
/// row per redirect hop, chain_index ascending). `downloads.tab_url` is only
/// the page that INITIATED the download and is frequently a different host —
/// or empty — so reporting it as `source_url` named the wrong origin
/// (BUG-223). Schemas before the chain table (meta.version 20, the plaso
/// reference) carry the download URL in `downloads.url` itself; that is read
/// when no chain exists, and labelled as such.
fn parse_chrome_downloads(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
    artifacts: &mut Vec<Artifact>,
) -> Result<()> {
    if !table_exists(conn, "downloads")? {
        return Ok(());
    }
    let Some(downloads) = resolved_plan(
        conn,
        &CHROME_HISTORY_SUPPORT,
        "downloads",
        CHROME_DOWNLOADS,
        CHROME_DOWNLOADS_OPTIONAL,
        artifacts,
        case_id,
        parent_id,
    )?
    else {
        return Ok(());
    };
    let chains = if table_exists(conn, "downloads_url_chains")? {
        resolved_plan(
            conn,
            &CHROME_HISTORY_SUPPORT,
            "downloads_url_chains",
            CHROME_URL_CHAINS,
            &[],
            artifacts,
            case_id,
            parent_id,
        )?
    } else {
        None
    };

    let (chain_first, chain_last) = match &chains {
        Some(c) => (
            format!(
                "(SELECT c.{url} FROM downloads_url_chains c WHERE c.{id} = d.id \
                 ORDER BY c.{index} ASC LIMIT 1)",
                url = col(c, "url"),
                id = col(c, "id"),
                index = col(c, "chain_index"),
            ),
            format!(
                "(SELECT c.{url} FROM downloads_url_chains c WHERE c.{id} = d.id \
                 ORDER BY c.{index} DESC LIMIT 1)",
                url = col(c, "url"),
                id = col(c, "id"),
                index = col(c, "chain_index"),
            ),
        ),
        None => ("NULL".to_string(), "NULL".to_string()),
    };
    let sql = format!(
        "SELECT d.{target}, {tab_url}, d.{total}, d.{start}, {end}, {danger}, {opened}, \
                {chain_first}, {chain_last}, {direct_url} \
         FROM downloads d \
         ORDER BY d.{start} DESC, d.{target} ASC, {tab_url} ASC, {end} ASC, d.{total} ASC \
         LIMIT ?1",
        target = col(&downloads, "target_path"),
        total = col(&downloads, "total_bytes"),
        start = col(&downloads, "start_time"),
        tab_url = opt(&downloads, "tab_url", "d"),
        end = opt(&downloads, "end_time", "d"),
        danger = opt(&downloads, "danger_type", "d"),
        opened = opt(&downloads, "opened", "d"),
        direct_url = opt(&downloads, "url", "d"),
    );
    // Schema drift used to skip every download silently (the `prepare`
    // Result was discarded). Emit a ParseFailed record instead, so the
    // examiner sees that downloads were present but unreadable, and keep the
    // history artifacts already collected above.
    match download_records(conn, &sql, case_id, parent_id, max_entries) {
        Ok(mut downloads) => artifacts.append(&mut downloads),
        Err(e) => {
            warn!("Failed to parse Chrome downloads table: {}", e);
            artifacts.push(
                Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "BrowserDownloadIncomplete",
                        "subtype": "browser_download_status",
                        "browser": "Chrome/Edge",
                        "status": "ParseFailed",
                        "error": e.to_string(),
                        "source_table": "downloads",
                        "content_incomplete": true,
                        "content_incomplete_reason": "unresolved_structure",
                        "content_incomplete_detail": format!(
                            concat!(
                                "the Chrome downloads table would not read, so no ",
                                "download was recovered from this profile: {}"
                            ),
                            e
                        ),
                        "detail": format!(
                            concat!(
                                "the Chrome downloads table would not read, so no ",
                                "download was recovered from this profile: {}"
                            ),
                            e
                        ),
                        "name": "Chrome downloads (parse failed)",
                    }),
                )
                .with_parent(parent_id)
                .with_subtype("browser_download_status"),
            );
        }
    }
    Ok(())
}

/// Read the Chrome `downloads` table with the given SELECT (column order fixed
/// by [`parse_chrome_downloads`]). Split out so a prepare/query failure is an
/// `Err` the caller can surface, instead of a silently skipped table.
///
/// The walk is newest-first, so hitting `max_entries` drops the OLDEST
/// downloads; that appends a `parse_incomplete` marker rather than letting the
/// listing read as every file the profile ever fetched.
fn download_records(
    conn: &Connection,
    sql: &str,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let walk = CappedWalk {
        sql,
        source_table: "downloads",
        marker_type: "BrowserDownloadIncomplete",
        what: "Chrome downloads",
        max_entries,
    };
    walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
        let target_path = row.get::<_, Option<String>>(0)?;
        let tab_url = row.get::<_, Option<String>>(1)?;
        let total_bytes = row.get::<_, i64>(2)?;
        let start_time = row.get::<_, i64>(3)?;
        // Optional columns: absent from older real schemas, read as NULL
        // there, and then omitted rather than invented.
        let end_time = row.get::<_, Option<i64>>(4)?;
        let danger_type = row.get::<_, Option<i64>>(5)?;
        let opened = row.get::<_, Option<i64>>(6)?;
        let chain_first = row.get::<_, Option<String>>(7)?;
        let chain_last = row.get::<_, Option<String>>(8)?;
        let direct_url = row.get::<_, Option<String>>(9)?;

        let target = target_path.unwrap_or_default();
        let file_name = target.rsplit(['/', '\\']).next().unwrap_or("unknown");
        let tab_url = tab_url.filter(|s| !s.is_empty());
        let chain_first = chain_first.filter(|s| !s.is_empty());
        let chain_last = chain_last.filter(|s| !s.is_empty());
        let direct_url = direct_url.filter(|s| !s.is_empty());

        // Final hop = the URL actually fetched; first hop = what the user
        // clicked. Prefer the final hop, then the first, then the pre-chain
        // schema's own `downloads.url`, then the initiating tab.
        // `source_url_origin` states which one it is rather than letting the
        // examiner assume.
        let (source_url, origin) = match (&chain_last, &chain_first, &direct_url, &tab_url) {
            (Some(u), _, _, _) => (u.clone(), "url_chain_final"),
            (None, Some(u), _, _) => (u.clone(), "url_chain_start"),
            (None, None, Some(u), _) => (u.clone(), "downloads_url"),
            (None, None, None, Some(u)) => (u.clone(), "tab_url"),
            (None, None, None, None) => (String::new(), "unknown"),
        };

        let mut metadata = json!({
            "type": "BrowserDownload",
            "subtype": "browser_download",
            "browser": "Chrome/Edge",
            "target_path": target,
            "source_url": source_url,
            "source_url_origin": origin,
            "url_chain_start": chain_first,
            "url_chain_final": chain_last,
            "tab_url": tab_url,
            "total_bytes": total_bytes,
            "start_time": webkit_us_to_unix_secs(start_time),
            "start_time_us": webkit_us_to_unix_us(start_time),
            "end_time": end_time.and_then(webkit_us_to_unix_secs),
            "end_time_us": end_time.and_then(webkit_us_to_unix_us),
            "name": format!("Download: {}", file_name),
        });
        if let Some(danger_type) = danger_type {
            metadata["danger_type"] = json!(danger_type);
        }
        if let Some(opened) = opened {
            metadata["was_opened"] = json!(opened != 0);
        }

        Ok(vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(parent_id)
        .with_subtype("browser_download")])
    })
}

/// Parse Firefox places.sqlite database.
///
/// Schema: `moz_places` has (id, url, title, visit_count, last_visit_date),
/// `moz_historyvisits` has (id, place_id, visit_date, visit_type).
/// Timestamps are PRTime (microseconds since Unix epoch).
///
/// Columns are resolved through a [`ColumnPlan`] before each query is written;
/// see [`parse_chrome`].
///
/// `max_entries` bounds the visit / places walk; the bookmark inventory has its
/// own [`MAX_BOOKMARK_ENTRIES`] budget. Either bound being reached appends a
/// `parse_incomplete` marker, so a truncated profile is never presented as the
/// user's complete browsing history or bookmark set.
fn parse_firefox(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();

    let has_places = table_exists(conn, "moz_places")?;

    if !has_places {
        warn!("Firefox places.sqlite missing 'moz_places' table");
        return Ok(artifacts);
    }
    let Some(places) = resolved_plan(
        conn,
        &FIREFOX_PLACES_SUPPORT,
        "moz_places",
        FIREFOX_PLACES,
        &[],
        &mut artifacts,
        case_id,
        parent_id,
    )?
    else {
        return Ok(artifacts);
    };

    let visits = if table_exists(conn, "moz_historyvisits")? {
        resolved_plan(
            conn,
            &FIREFOX_PLACES_SUPPORT,
            "moz_historyvisits",
            FIREFOX_VISITS,
            &[],
            &mut artifacts,
            case_id,
            parent_id,
        )?
    } else {
        None
    };

    if let Some(visits) = visits {
        let sql = format!(
            "SELECT p.{url}, p.{title}, v.{visit_date}, p.{visit_count}, v.{visit_type}
             FROM moz_historyvisits v
             JOIN moz_places p ON v.{place_id} = p.{id}
             ORDER BY v.{visit_date} DESC, p.{url} ASC, v.{visit_type} ASC
             LIMIT ?1",
            url = col(&places, "url"),
            title = col(&places, "title"),
            visit_count = col(&places, "visit_count"),
            id = col(&places, "id"),
            place_id = col(&visits, "place_id"),
            visit_date = col(&visits, "visit_date"),
            visit_type = col(&visits, "visit_type"),
        );
        let walk = CappedWalk {
            sql: &sql,
            source_table: "moz_historyvisits",
            marker_type: "BrowserHistoryIncomplete",
            what: "Firefox visits",
            max_entries,
        };
        artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
            let url = row.get::<_, String>(0)?;
            let title = row.get::<_, Option<String>>(1)?;
            let visit_date = row.get::<_, i64>(2)?;
            let visit_count = row.get::<_, i64>(3)?;
            let visit_type = row.get::<_, i64>(4)?;

            // PRTime is microseconds since Unix epoch; null when unset,
            // full microsecond precision in _us
            let title_str = title.unwrap_or_default();
            let visit_time = prtime_to_unix_secs(visit_date);
            let mut out = Vec::new();
            if let Some(ts) = visit_time {
                out.push(make_visit_timeline_event(
                    case_id, parent_id, "Firefox", &url, &title_str, ts,
                ));
            }
            let metadata = json!({
                "type": "BrowserHistory",
                "subtype": "browser_visit",
                "browser": "Firefox",
                "url": url,
                "title": title_str,
                "visit_time": visit_time,
                "visit_time_us": if visit_date != 0 { Some(visit_date) } else { None },
                "visit_count": visit_count,
                "transition_type": firefox_transition_name(visit_type),
                "name": format!("Visit: {}", truncate_url(&url, 80)),
            });
            out.push(
                Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(parent_id)
                    .with_subtype("browser_visit"),
            );
            Ok(out)
        })?);
    } else {
        // Fallback: just places
        let sql = format!(
            "SELECT {url}, {title}, {visit_count}, {last_visit_date} FROM moz_places \
             WHERE {visit_count} > 0 ORDER BY {last_visit_date} DESC, {url} ASC LIMIT ?1",
            url = col(&places, "url"),
            title = col(&places, "title"),
            visit_count = col(&places, "visit_count"),
            last_visit_date = col(&places, "last_visit_date"),
        );
        let walk = CappedWalk {
            sql: &sql,
            source_table: "moz_places",
            marker_type: "BrowserHistoryIncomplete",
            what: "Firefox places",
            max_entries,
        };
        artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
            let url = row.get::<_, String>(0)?;
            let title = row.get::<_, Option<String>>(1)?;
            let visit_count = row.get::<_, i64>(2)?;
            let last_visit_date = row.get::<_, Option<i64>>(3)?;

            // NULL/0 stays absent instead of a fabricated 1970 timestamp
            let visit_date_us = last_visit_date.filter(|&d| d != 0);
            let title_str = title.unwrap_or_default();
            let visit_time = visit_date_us.and_then(prtime_to_unix_secs);
            let mut out = Vec::new();
            if let Some(ts) = visit_time {
                out.push(make_visit_timeline_event(
                    case_id, parent_id, "Firefox", &url, &title_str, ts,
                ));
            }
            let metadata = json!({
                "type": "BrowserHistory",
                "subtype": "browser_visit",
                "browser": "Firefox",
                "url": url,
                "title": title_str,
                "visit_time": visit_time,
                "visit_time_us": visit_date_us,
                "visit_count": visit_count,
                "name": format!("Visit: {}", truncate_url(&url, 80)),
            });
            out.push(
                Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(parent_id)
                    .with_subtype("browser_visit"),
            );
            Ok(out)
        })?);
    }

    // Firefox bookmarks from moz_bookmarks (if present)
    if table_exists(conn, "moz_bookmarks")? {
        let Some(bookmarks) = resolved_plan(
            conn,
            &FIREFOX_PLACES_SUPPORT,
            "moz_bookmarks",
            FIREFOX_BOOKMARKS,
            &[],
            &mut artifacts,
            case_id,
            parent_id,
        )?
        else {
            return Ok(artifacts);
        };
        // Schema drift used to drop every bookmark without a trace: both the
        // `prepare` and the `query_map` Results were pattern-matched away with
        // `if let Ok`, so a table that existed but could not be read rendered
        // exactly like a profile with no bookmarks. Surface the failure as its
        // own record, the same way the Chrome downloads table does.
        match bookmark_records(
            conn,
            &places,
            &bookmarks,
            case_id,
            parent_id,
            MAX_BOOKMARK_ENTRIES,
        ) {
            Ok(mut bookmarks) => artifacts.append(&mut bookmarks),
            Err(e) => {
                warn!("Failed to parse Firefox moz_bookmarks table: {}", e);
                artifacts.push(
                    Artifact::new(
                        case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        json!({
                            "type": "BrowserBookmarkIncomplete",
                            "subtype": "browser_bookmark_status",
                            "browser": "Firefox",
                            "status": "ParseFailed",
                            "error": e.to_string(),
                            "source_table": "moz_bookmarks",
                            "content_incomplete": true,
                            "content_incomplete_reason": "unresolved_structure",
                            "content_incomplete_detail": format!(
                                concat!(
                                    "the Firefox bookmarks tables would not read, so no ",
                                    "bookmark was recovered from this profile: {}"
                                ),
                                e
                            ),
                            "detail": format!(
                                concat!(
                                    "the Firefox bookmarks tables would not read, so no ",
                                    "bookmark was recovered from this profile: {}"
                                ),
                                e
                            ),
                            "name": "Firefox bookmarks (parse failed)",
                        }),
                    )
                    .with_parent(parent_id)
                    .with_subtype("browser_bookmark_status"),
                );
            }
        }
    }

    Ok(artifacts)
}

/// Read the Firefox `moz_bookmarks` inventory (bookmark rows only, `type = 1`).
///
/// Split out so a prepare/query failure is an `Err` the caller can report,
/// rather than a table that existed but silently produced nothing. Hitting
/// `max_entries` appends a `parse_incomplete` marker: the walk is
/// newest-added-first, so the bookmarks lost are the oldest ones.
fn bookmark_records(
    conn: &Connection,
    places: &ColumnPlan,
    bookmarks: &ColumnPlan,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let sql = format!(
        "SELECT b.{title}, p.{url}, b.{date_added}, b.{last_modified}
         FROM moz_bookmarks b
         JOIN moz_places p ON b.{fk} = p.{id}
         WHERE b.{kind} = 1 AND p.{url} IS NOT NULL
         ORDER BY b.{date_added} DESC, p.{url} ASC, b.{title} ASC, b.{last_modified} ASC
         LIMIT ?1",
        title = col(bookmarks, "title"),
        date_added = col(bookmarks, "dateAdded"),
        last_modified = col(bookmarks, "lastModified"),
        fk = col(bookmarks, "fk"),
        kind = col(bookmarks, "type"),
        url = col(places, "url"),
        id = col(places, "id"),
    );
    let walk = CappedWalk {
        sql: &sql,
        source_table: "moz_bookmarks",
        marker_type: "BrowserBookmarkIncomplete",
        what: "Firefox bookmarks",
        max_entries,
    };
    walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
        let title = row.get::<_, Option<String>>(0)?;
        let url = row.get::<_, String>(1)?;
        let date_added = row.get::<_, i64>(2)?;
        let last_modified = row.get::<_, i64>(3)?;

        let metadata = json!({
            "type": "BrowserBookmark",
            "subtype": "browser_bookmark",
            "browser": "Firefox",
            "title": title.unwrap_or_default(),
            "url": url,
            "date_added": prtime_to_unix_secs(date_added),
            "date_added_us": if date_added != 0 { Some(date_added) } else { None },
            "last_modified": prtime_to_unix_secs(last_modified),
            "last_modified_us": if last_modified != 0 { Some(last_modified) } else { None },
            "name": format!("Bookmark: {}", truncate_url(&url, 80)),
        });

        Ok(vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(parent_id)
        .with_subtype("browser_bookmark")])
    })
}

/// Unix **microseconds** for a decoded Safari visit instant, in the same
/// `visit_time_us` shape the Chrome and Firefox walks publish.
///
/// Microseconds, not nanoseconds, because that is the unit every other browser
/// record in this file already speaks — a consumer sorting a mixed browsing
/// history reads one field. The sub-microsecond remainder is dropped by
/// flooring rather than rounding: an f64 seconds-since-2001 column has around
/// 100 ns of resolution at present-day values, so that remainder is below what
/// the source can express, and flooring can only place a visit fractionally
/// earlier — never later than it happened.
fn safari_visit_us((secs, nanos): (i64, u32)) -> Option<i64> {
    secs.checked_mul(1_000_000)?
        .checked_add(i64::from(nanos / 1_000))
}

/// Parse Safari History.db database.
///
/// Schema: `history_items` has (id, url, visit_count),
/// `history_visits` has (id, history_item, visit_time, title).
/// Timestamps are Core Data epoch (seconds since 2001-01-01), and the column is
/// REAL: the fraction rides along in `visit_time_us`.
///
/// Columns are resolved through a [`ColumnPlan`] before each query is written;
/// see [`parse_chrome`].
///
/// `max_entries` bounds the walk. When it is reached a `parse_incomplete`
/// marker is appended, because a Safari listing that stopped early is otherwise
/// indistinguishable from one that recovered every visit on the device.
fn parse_safari(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();

    let has_items = table_exists(conn, "history_items")?;

    if !has_items {
        warn!("Safari History.db missing 'history_items' table");
        return Ok(artifacts);
    }
    let Some(items) = resolved_plan(
        conn,
        &SAFARI_HISTORY_SUPPORT,
        "history_items",
        SAFARI_ITEMS,
        &[],
        &mut artifacts,
        case_id,
        parent_id,
    )?
    else {
        return Ok(artifacts);
    };

    let visits = if table_exists(conn, "history_visits")? {
        resolved_plan(
            conn,
            &SAFARI_HISTORY_SUPPORT,
            "history_visits",
            SAFARI_VISITS,
            &[],
            &mut artifacts,
            case_id,
            parent_id,
        )?
    } else {
        None
    };

    if let Some(visits) = visits {
        let sql = format!(
            "SELECT hi.{url}, hv.{title}, hv.{visit_time}, hi.{visit_count}
             FROM history_visits hv
             JOIN history_items hi ON hv.{history_item} = hi.{id}
             ORDER BY hv.{visit_time} DESC, hi.{url} ASC, hv.{title} ASC
             LIMIT ?1",
            url = col(&items, "url"),
            visit_count = col(&items, "visit_count"),
            id = col(&items, "id"),
            title = col(&visits, "title"),
            visit_time = col(&visits, "visit_time"),
            history_item = col(&visits, "history_item"),
        );
        let walk = CappedWalk {
            sql: &sql,
            source_table: "history_visits",
            marker_type: "BrowserHistoryIncomplete",
            what: "Safari visits",
            max_entries,
        };
        artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
            let url = row.get::<_, String>(0)?;
            let title = row.get::<_, Option<String>>(1)?;
            let visit_time_coredata = row.get::<_, f64>(2)?;
            let visit_count = row.get::<_, i64>(3)?;

            // Core Data timestamp: seconds since 2001-01-01 00:00:00 UTC.
            // None for the zero sentinel, so it never surfaces as
            // 2001-01-01 — on the timeline OR on the record below.
            //
            // `visit_time` is a REAL column and the fraction is what orders two
            // visits inside the same second — a redirect chain lands several
            // there. It is decoded and published as `visit_time_us`, the same
            // sub-second field the Chrome and Firefox walks below carry, so one
            // consumer reads all three.
            let visit_parts = cocoa_secs_to_unix_nanos(visit_time_coredata);
            let unix_timestamp = visit_parts.map(|(secs, _)| secs);
            let visit_time_us = visit_parts.and_then(safari_visit_us);
            let title_str = title.unwrap_or_default();
            let mut out = Vec::new();
            if let Some(ts) = unix_timestamp {
                out.push(make_visit_timeline_event(
                    case_id, parent_id, "Safari", &url, &title_str, ts,
                ));
            }
            let metadata = json!({
                "type": "BrowserHistory",
                "subtype": "browser_visit",
                "browser": "Safari",
                "url": url,
                "title": title_str,
                "visit_time": unix_timestamp,
                "visit_time_us": visit_time_us,
                "visit_count": visit_count,
                "name": format!("Visit: {}", truncate_url(&url, 80)),
            });
            out.push(
                Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(parent_id)
                    .with_subtype("browser_visit"),
            );
            Ok(out)
        })?);
    } else {
        // Fallback: just history_items. Ordered by visit_count, so a cap here
        // drops the LEAST-visited URLs, not the oldest; the marker's detail text
        // is written in newest-first terms, and the `source_table` is what tells
        // the examiner which ordering applied.
        let sql = format!(
            "SELECT {url}, {visit_count} FROM history_items \
             ORDER BY {visit_count} DESC, {url} ASC LIMIT ?1",
            url = col(&items, "url"),
            visit_count = col(&items, "visit_count"),
        );
        let walk = CappedWalk {
            sql: &sql,
            source_table: "history_items",
            marker_type: "BrowserHistoryIncomplete",
            what: "Safari items",
            max_entries,
        };
        artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
            let url = row.get::<_, String>(0)?;
            let visit_count = row.get::<_, i64>(1)?;

            let metadata = json!({
                "type": "BrowserHistory",
                "subtype": "browser_visit",
                "browser": "Safari",
                "url": url,
                "title": "",
                // No per-visit timestamp exists in this fallback path
                "visit_time": null,
                "visit_count": visit_count,
                "name": format!("Visit: {}", truncate_url(&url, 80)),
            });

            Ok(vec![Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                metadata,
            )
            .with_parent(parent_id)
            .with_subtype("browser_visit")])
        })?);
    }

    Ok(artifacts)
}

// --- Timestamp conversions ---
//
// The converters themselves live in `seance_time_util`
// (`webkit_us_to_unix_secs`, `webkit_us_to_unix_us`, `prtime_to_unix_secs`,
// `cocoa_secs_to_unix_nanos`). A doc comment describing the WebKit conversion
// — microseconds since 1601-01-01, `None` for 0, because "unset" must not
// surface as the year 1601 — stood here after the functions moved, so it was
// read by rustdoc as the opening of `parse_chrome_cookies` below.

/// Parse a Chrome/Edge `Cookies` database (the `cookies` table). Modern Chrome
/// encrypts the value (`encrypted_value` blob) with an OS-bound key, so plaintext
/// values are usually empty; the host/name/path/timestamps are always readable.
/// The oldest real jar this parser was validated against (meta.version 5) has
/// no `encrypted_value` at all and names its flags `secure` / `httponly`; the
/// candidate lists absorb both.
///
/// The walk is ordered newest-created-first and bounded by `max_entries`. Both
/// matter: without the ORDER BY, *which* cookies survived a cap was whatever
/// order SQLite happened to return, so two runs over the same evidence could
/// list different sites; without the marker, a truncated jar reads as proof the
/// remaining domains were never contacted.
fn parse_chrome_cookies(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let has = table_exists(conn, "cookies")?;
    if !has {
        warn!("Chrome Cookies DB missing 'cookies' table");
        return Ok(artifacts);
    }
    let Some(cookies) = resolved_plan(
        conn,
        &CHROME_COOKIES_SUPPORT,
        "cookies",
        CHROME_COOKIES,
        CHROME_COOKIES_OPTIONAL,
        &mut artifacts,
        case_id,
        parent_id,
    )?
    else {
        return Ok(artifacts);
    };

    let sql = format!(
        "SELECT {host}, {name}, {value}, {encrypted}, {path}, {creation}, {expires}, \
         {last_access}, {secure}, {httponly} FROM cookies \
         ORDER BY {creation} DESC, {host} ASC, {name} ASC, {path} ASC LIMIT ?1",
        host = col(&cookies, "host_key"),
        name = col(&cookies, "name"),
        value = col(&cookies, "value"),
        encrypted = opt(&cookies, "encrypted_value", ""),
        path = col(&cookies, "path"),
        creation = col(&cookies, "creation_utc"),
        expires = col(&cookies, "expires_utc"),
        last_access = col(&cookies, "last_access_utc"),
        secure = col(&cookies, "is_secure"),
        httponly = col(&cookies, "is_httponly"),
    );
    let walk = CappedWalk {
        sql: &sql,
        source_table: "cookies",
        marker_type: "BrowserCookieIncomplete",
        what: "Chrome cookies",
        max_entries,
    };
    artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
        let host = row.get::<_, String>(0)?;
        let name = row.get::<_, String>(1)?;
        let value = row.get::<_, String>(2).unwrap_or_default();
        let enc = row.get::<_, Vec<u8>>(3).unwrap_or_default();
        let path = row.get::<_, String>(4).unwrap_or_default();
        let creation = row.get::<_, i64>(5).unwrap_or(0);
        let expires = row.get::<_, i64>(6).unwrap_or(0);
        let last_access = row.get::<_, i64>(7).unwrap_or(0);
        let secure = row.get::<_, i64>(8).unwrap_or(0);
        let httponly = row.get::<_, i64>(9).unwrap_or(0);

        let encrypted = value.is_empty() && !enc.is_empty();
        let mut metadata = json!({
            "type": "BrowserCookie",
            "subtype": "browser_cookie",
            "browser": "Chrome/Edge",
            "host": host,
            "cookie_name": name,
            "path": path,
            "value_encrypted": encrypted,
            "creation_time": webkit_us_to_unix_secs(creation),
            "expiry_time": webkit_us_to_unix_secs(expires),
            "last_access": webkit_us_to_unix_secs(last_access),
            "is_secure": secure != 0,
            "is_httponly": httponly != 0,
            "name": format!("Cookie: {} ({})", host, name),
        });
        if !value.is_empty() {
            metadata["value"] = json!(value);
        }
        Ok(vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(parent_id)
        .with_subtype("browser_cookie")])
    })?);
    Ok(artifacts)
}

/// Parse a Firefox `cookies.sqlite` database (the `moz_cookies` table). Firefox
/// stores cookie values in plaintext.
///
/// Ordered newest-created-first and bounded by `max_entries`, for the same
/// reason as the Chrome jar: an unordered cap makes the surviving set arbitrary,
/// and an unflagged one makes a partial jar look like the whole one.
fn parse_firefox_cookies(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let has = table_exists(conn, "moz_cookies")?;
    if !has {
        warn!("Firefox cookies.sqlite missing 'moz_cookies' table");
        return Ok(artifacts);
    }
    let Some(cookies) = resolved_plan(
        conn,
        &FIREFOX_COOKIES_SUPPORT,
        "moz_cookies",
        FIREFOX_COOKIES,
        &[],
        &mut artifacts,
        case_id,
        parent_id,
    )?
    else {
        return Ok(artifacts);
    };

    let sql = format!(
        "SELECT {host}, {name}, {value}, {path}, {expiry}, {creation}, {last_accessed}, \
         {secure}, {httponly} FROM moz_cookies \
         ORDER BY {creation} DESC, {host} ASC, {name} ASC, {path} ASC LIMIT ?1",
        host = col(&cookies, "host"),
        name = col(&cookies, "name"),
        value = col(&cookies, "value"),
        path = col(&cookies, "path"),
        expiry = col(&cookies, "expiry"),
        creation = col(&cookies, "creationTime"),
        last_accessed = col(&cookies, "lastAccessed"),
        secure = col(&cookies, "isSecure"),
        httponly = col(&cookies, "isHttpOnly"),
    );
    let walk = CappedWalk {
        sql: &sql,
        source_table: "moz_cookies",
        marker_type: "BrowserCookieIncomplete",
        what: "Firefox cookies",
        max_entries,
    };
    artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
        let host = row.get::<_, String>(0)?;
        let name = row.get::<_, String>(1)?;
        let value = row.get::<_, String>(2).unwrap_or_default();
        let path = row.get::<_, String>(3).unwrap_or_default();
        // expiry: unix seconds; creationTime / lastAccessed: unix microseconds
        let expiry = row.get::<_, i64>(4).unwrap_or(0);
        let creation = row.get::<_, i64>(5).unwrap_or(0);
        let last_access = row.get::<_, i64>(6).unwrap_or(0);
        let secure = row.get::<_, i64>(7).unwrap_or(0);
        let httponly = row.get::<_, i64>(8).unwrap_or(0);

        let mut metadata = json!({
            "type": "BrowserCookie",
            "subtype": "browser_cookie",
            "browser": "Firefox",
            "host": host,
            "cookie_name": name,
            "path": path,
            "value_encrypted": false,
            "creation_time": prtime_to_unix_secs(creation),
            "expiry_time": if expiry > 0 { Some(expiry) } else { None },
            "last_access": prtime_to_unix_secs(last_access),
            "is_secure": secure != 0,
            "is_httponly": httponly != 0,
            "name": format!("Cookie: {} ({})", host, name),
        });
        if !value.is_empty() {
            metadata["value"] = json!(value);
        }
        Ok(vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(parent_id)
        .with_subtype("browser_cookie")])
    })?);
    Ok(artifacts)
}

/// One decoded binarycookies record, before it becomes a `BrowserCookie`
/// artifact. Field names follow this crate's convention (`host`, not Apple's
/// own `url`) rather than the source format's — see [`parse_binarycookies_record`].
struct BinaryCookieRecord {
    host: String,
    name: String,
    path: String,
    value: String,
    flags: u32,
    creation: f64,
    expiration: f64,
}

/// Parse one binarycookies page header: a 4-byte page signature (read but not
/// checked — see below), a 4-byte little-endian record count, and that many
/// 4-byte little-endian page-relative record offsets. Returns the offsets.
///
/// The page signature is `\x00\x00\x01\x00` in every page of the reference
/// jar at `reference/plaso/test_data/Cookies.binarycookies`, but neither the
/// reference parser (`reference/plaso/plaso/parsers/safari_cookies.py`) nor
/// its dtFabric field list (`safari_cookies.yaml`, `binarycookies_page_header`)
/// asserts a fixed value for it, so this module reads past it rather than
/// refusing the page on it: a byte Apple changes there should not turn a page
/// of real cookies into "no cookies were here".
///
/// Between the offsets array and the first record sits a 4-byte all-zero
/// field ([`BC_END_OF_PAGE_MARKER_LEN`]) that neither the reference parser nor
/// its field list names either. It is not a record: every offset observed in
/// the reference jar already counts past it (`offsets[0] ==
/// BC_PAGE_HEADER_LEN + 4*record_count + BC_END_OF_PAGE_MARKER_LEN`), so this
/// function accounts for its length when checking the page is long enough to
/// hold the offsets it declares, then skips it — it is never read as a field
/// in its own right, because nothing here depends on its value.
fn parse_binarycookies_page_header(page: &[u8]) -> Result<Vec<usize>, String> {
    if page.len() < BC_PAGE_HEADER_LEN {
        return Err(format!(
            "page is {} bytes, too short for the {BC_PAGE_HEADER_LEN}-byte page header",
            page.len()
        ));
    }
    let record_count = u32::from_le_bytes([page[4], page[5], page[6], page[7]]) as usize;
    let offsets_bytes = record_count.checked_mul(4).ok_or_else(|| {
        format!("page declares {record_count} records, which overflows the offset table size")
    })?;
    let offsets_end = BC_PAGE_HEADER_LEN
        .checked_add(offsets_bytes)
        .ok_or_else(|| "page's offset table overflows".to_string())?;
    let page_header_total = offsets_end
        .checked_add(BC_END_OF_PAGE_MARKER_LEN)
        .ok_or_else(|| "page header overflows with its end-of-page marker".to_string())?;
    if page.len() < page_header_total {
        return Err(format!(
            "page declares {record_count} records, which needs a {page_header_total}-byte \
             header (offset table plus the {BC_END_OF_PAGE_MARKER_LEN}-byte end-of-page \
             marker), but the page is only {} bytes",
            page.len()
        ));
    }
    let mut offsets = Vec::with_capacity(record_count);
    let mut pos = BC_PAGE_HEADER_LEN;
    for _ in 0..record_count {
        offsets.push(
            u32::from_le_bytes([page[pos], page[pos + 1], page[pos + 2], page[pos + 3]]) as usize,
        );
        pos += 4;
    }
    Ok(offsets)
}

/// Read a NUL-terminated cookie string at `offset` bytes into `record` (the
/// bytes of ONE record, already bounded to its declared `size` — see
/// [`parse_binarycookies_record`]). A zero offset means the field is absent,
/// the same convention the reference parser uses
/// (`if record_header.url_offset:` in `safari_cookies.py`): the 56-byte fixed
/// header ([`BC_RECORD_HEADER_LEN`]) is never itself a valid string, so 0
/// cannot be a real offset.
fn read_binarycookies_cstring(record: &[u8], offset: usize) -> Result<String, String> {
    if offset == 0 {
        return Ok(String::new());
    }
    if offset >= record.len() {
        return Err(format!(
            "string offset {offset} is outside the {}-byte record",
            record.len()
        ));
    }
    let bytes = &record[offset..];
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| format!("string at offset {offset} is not NUL-terminated"))?;
    // Cookie text is host/path/name/value data from the evidence, not a
    // Rust-internal invariant, so a byte sequence that is not valid UTF-8 is
    // published lossily (U+FFFD) rather than failing the whole record.
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// Parse one binarycookies record at `record_offset` bytes into `page`.
///
/// Layout (little-endian throughout), confirmed field-by-field against
/// `reference/plaso/plaso/parsers/safari_cookies.yaml`
/// (`binarycookies_record_header`) and against the first record of
/// `reference/plaso/test_data/Cookies.binarycookies` (this module's test
/// fixture is modelled on that record):
///
///   size (u32), unknown1 (u32), flags (u32), unknown2 (u32),
///   url_offset (u32), name_offset (u32), path_offset (u32), value_offset (u32),
///   unknown3 (u64), expiration_time (f64), creation_time (f64),
///   then the NUL-terminated strings the four offsets above point to.
///
/// `unknown1`/`unknown2`/`unknown3` are read (so the fixed offsets after them
/// are right) but never published: the reference parser leaves them
/// unnamed and this crate has no independent way to say what they mean.
///
/// Apple's own name for the domain field is `url` (`url_offset` in the field
/// list above), but what it actually holds is the cookie's domain —
/// `en.wikipedia.org`, `.apple.com` — not a URL with a scheme, so this
/// function publishes it as `host`, the field name Chrome's and Firefox's
/// cookie rows in this crate already use for the same thing.
fn parse_binarycookies_record(
    page: &[u8],
    record_offset: usize,
) -> Result<BinaryCookieRecord, String> {
    let header_end = record_offset
        .checked_add(BC_RECORD_HEADER_LEN)
        .ok_or_else(|| format!("record offset {record_offset} overflows the page"))?;
    if header_end > page.len() {
        return Err(format!(
            "record at offset {record_offset} needs {BC_RECORD_HEADER_LEN} bytes for its fixed \
             header, but the page is only {} bytes",
            page.len()
        ));
    }
    let rec = &page[record_offset..];
    let u32_at = |o: usize| u32::from_le_bytes([rec[o], rec[o + 1], rec[o + 2], rec[o + 3]]);
    let f64_at = |o: usize| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&rec[o..o + 8]);
        f64::from_le_bytes(buf)
    };

    let size = u32_at(0) as usize;
    let flags = u32_at(8);
    let url_offset = u32_at(16) as usize;
    let name_offset = u32_at(20) as usize;
    let path_offset = u32_at(24) as usize;
    let value_offset = u32_at(28) as usize;
    let expiration = f64_at(40);
    let creation = f64_at(48);

    if size < BC_RECORD_HEADER_LEN {
        return Err(format!(
            "record at offset {record_offset} declares a {size}-byte size, smaller than its \
             own {BC_RECORD_HEADER_LEN}-byte fixed header"
        ));
    }
    let record_end = record_offset.checked_add(size).ok_or_else(|| {
        format!("record at offset {record_offset} declares a size that overflows")
    })?;
    if record_end > page.len() {
        return Err(format!(
            "record at offset {record_offset} declares a {size}-byte size that runs past the \
             end of its {}-byte page",
            page.len()
        ));
    }
    let record_bytes = &rec[..size];

    Ok(BinaryCookieRecord {
        host: read_binarycookies_cstring(record_bytes, url_offset)?,
        name: read_binarycookies_cstring(record_bytes, name_offset)?,
        path: read_binarycookies_cstring(record_bytes, path_offset)?,
        value: read_binarycookies_cstring(record_bytes, value_offset)?,
        flags,
        creation,
        expiration,
    })
}

/// Build the `BrowserCookie` artifact for one decoded binarycookies record —
/// the same record shape Chrome's and Firefox's cookie jars emit above (host,
/// cookie_name, path, is_secure, is_httponly, value / value_encrypted), so the
/// existing viewer and Analysis categorisation need no Safari-specific case.
///
/// Two additions beyond that shape, both because this source can support
/// them and the SQLite jars cannot: `creation_time_us` / `expiry_time_us`
/// sub-second companions, decoded through the exact same
/// [`cocoa_secs_to_unix_nanos`] + `safari_visit_us` pair the Safari
/// `History.db` walk above uses for `visit_time_us` — binarycookies stores
/// both timestamps as the same Core Data REAL (seconds since 2001-01-01) that
/// `visit_time` is, with the same sub-second fraction. `value_encrypted` is
/// unconditionally `false`: unlike Chrome's OS-key-bound `encrypted_value`,
/// Safari's binarycookies format has no encrypted-value slot at all — a
/// stored value is always the plaintext the browser sent.
fn safari_binarycookie_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    rec: &BinaryCookieRecord,
) -> Artifact {
    let is_secure = rec.flags & SAFARI_COOKIE_FLAG_SECURE != 0;
    let is_httponly = rec.flags & SAFARI_COOKIE_FLAG_HTTPONLY != 0;

    let creation_parts = cocoa_secs_to_unix_nanos(rec.creation);
    let expiration_parts = cocoa_secs_to_unix_nanos(rec.expiration);

    let mut metadata = json!({
        "type": "BrowserCookie",
        "subtype": "browser_cookie",
        "browser": "Safari",
        "host": rec.host,
        "cookie_name": rec.name,
        "path": rec.path,
        "value_encrypted": false,
        "creation_time": creation_parts.map(|(s, _)| s),
        "creation_time_us": creation_parts.and_then(safari_visit_us),
        "expiry_time": expiration_parts.map(|(s, _)| s),
        "expiry_time_us": expiration_parts.and_then(safari_visit_us),
        "is_secure": is_secure,
        "is_httponly": is_httponly,
        "name": format!("Cookie: {} ({})", rec.host, rec.name),
    });
    if !rec.value.is_empty() {
        metadata["value"] = json!(rec.value);
    }
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(parent_id)
        .with_subtype("browser_cookie")
}

/// Parse Safari's own cookie jar, `Cookies.binarycookies` — Apple's own binary
/// format (magic `cook`), never a SQLite database and never a property list,
/// so it is handled entirely separately from every other cookie jar in this
/// crate.
///
/// File layout (big-endian header, then little-endian pages), confirmed
/// against the vendored reference parser and its field list
/// (`reference/plaso/plaso/parsers/safari_cookies.py`, `safari_cookies.yaml`)
/// and against the real jar at
/// `reference/plaso/test_data/Cookies.binarycookies`:
///
///   4-byte magic `cook`, 4-byte big-endian page count, that many 4-byte
///   big-endian page sizes, then the page bytes back to back — each page a
///   header ([`parse_binarycookies_page_header`]) followed by its records
///   ([`parse_binarycookies_record`]).
///
/// Both ways this can come up short are declared, and the distinction that
/// matters is the same one every non-SQLite walk in this file draws: a file
/// too short to hold even the `cook` header is a genuine determination that
/// this is not a binarycookies file at all (`Ok(vec![])`, same as the
/// Firefox session store's bad-magic case); a file whose OWN page table
/// declares more bytes than the file holds — the file source under-delivered,
/// or the file was truncated on disk — is not "no more cookies", so it is a
/// [`file_incomplete_marker`] instead. A page whose header will not parse, or
/// a record whose offsets will not, drops that one page or that one record
/// through [`RowDrops`] and keeps reading the rest — one damaged page must
/// not cost the whole jar. The walk is bounded by [`MAX_HISTORY_ENTRIES`], the
/// same cap every other cookie/history/autofill walk in this crate shares,
/// via [`CapCounter`] and [`cap_marker`] exactly as the SQL walks use them.
fn parse_safari_binarycookies(
    ds: &dyn DataSource,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Result<Vec<Artifact>> {
    let raw = match read_whole(ds, MAX_BINARYCOOKIES_BYTES) {
        Ok(bytes) => bytes,
        Err(short) => {
            let detail = match short.reason {
                IncompleteReason::CapReached => format!(
                    "the cookie jar is {} bytes, past the {}-byte read ceiling, so no cookie \
                     was extracted",
                    short.declared, MAX_BINARYCOOKIES_BYTES
                ),
                _ => format!(
                    "the source delivered {} of the {} bytes it declared, so the cookie jar \
                     could not be decoded",
                    short.read, short.declared
                ),
            };
            return Ok(vec![file_incomplete_marker(
                case_id,
                parent_id,
                "BrowserCookieIncomplete",
                file_name,
                &short,
                &detail,
            )]);
        }
    };

    // Too short to hold even the file header: a genuine determination that
    // this is not a binarycookies file, not a truncation of one — the same
    // convention `parse_firefox_session` uses for its `mozLz40\0` check.
    if raw.len() < 8 {
        warn!("Safari binarycookies file too short for a header");
        return Ok(Vec::new());
    }
    if &raw[0..4] != b"cook" {
        warn!("Not a Safari binarycookies file (bad magic)");
        return Ok(Vec::new());
    }
    let page_count = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;

    let page_table_bytes = match page_count.checked_mul(4) {
        Some(n) => n,
        None => {
            let detail = format!(
                "the file declares {page_count} pages, which overflows the page-size table \
                 size, so no page was read"
            );
            return Ok(vec![file_incomplete_marker(
                case_id,
                parent_id,
                "BrowserCookieIncomplete",
                file_name,
                &ShortFile {
                    reason: IncompleteReason::UnresolvedStructure,
                    declared: raw.len() as u64,
                    read: raw.len() as u64,
                },
                &detail,
            )]);
        }
    };
    let page_table_end = 8usize + page_table_bytes;

    if raw.len() < page_table_end {
        let detail = format!(
            "the file declares {page_count} pages, which needs a {page_table_end}-byte \
             page-size table, but the file is only {} bytes, so no page was read",
            raw.len()
        );
        return Ok(vec![file_incomplete_marker(
            case_id,
            parent_id,
            "BrowserCookieIncomplete",
            file_name,
            &ShortFile {
                reason: IncompleteReason::UnresolvedStructure,
                declared: page_table_end as u64,
                read: raw.len() as u64,
            },
            &detail,
        )]);
    }

    let mut page_sizes = Vec::with_capacity(page_count);
    let mut pos = 8usize;
    for _ in 0..page_count {
        page_sizes.push(
            u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]) as usize,
        );
        pos += 4;
    }
    let total_declared_bytes = page_sizes.iter().fold(page_table_end as u64, |acc, &s| {
        acc.saturating_add(s as u64)
    });

    let mut artifacts = Vec::new();
    let mut cap = CapCounter::new(MAX_HISTORY_ENTRIES);
    let mut drops = RowDrops::new();
    let mut recovered = 0usize;

    'pages: for (page_index, &page_size) in page_sizes.iter().enumerate() {
        let page_end = pos + page_size;
        if page_end > raw.len() {
            // The jar's own page table declares more bytes than the file
            // holds: every page from here on is unreachable. Reported once,
            // not once per unreachable page, so the record count downstream
            // is not accompanied by dozens of identical markers.
            let detail = format!(
                "the jar declares {page_count} pages totalling {total_declared_bytes} bytes, \
                 but the file holds {} — page {page_index} of {page_count} and every page \
                 after it were not read",
                raw.len()
            );
            artifacts.push(file_incomplete_marker(
                case_id,
                parent_id,
                "BrowserCookieIncomplete",
                file_name,
                &ShortFile {
                    reason: IncompleteReason::ShortRead,
                    declared: total_declared_bytes,
                    read: raw.len() as u64,
                },
                &detail,
            ));
            break 'pages;
        }
        let page = &raw[pos..page_end];
        pos = page_end;

        let offsets = match parse_binarycookies_page_header(page) {
            Ok(offsets) => offsets,
            Err(e) => {
                drops.record(format!("page {page_index}: {e}"));
                continue;
            }
        };

        for record_offset in offsets {
            if !cap.admit() {
                break 'pages;
            }
            match parse_binarycookies_record(page, record_offset) {
                Ok(rec) => {
                    recovered += 1;
                    artifacts.push(safari_binarycookie_artifact(case_id, parent_id, &rec));
                }
                Err(e) => {
                    drops.record(format!("page {page_index} record@0x{record_offset:x}: {e}"))
                }
            }
        }
    }

    if cap.truncated() {
        artifacts.push(cap_marker(
            case_id,
            parent_id,
            "BrowserCookieIncomplete",
            file_name,
            &cap,
        ));
    }
    if let Some(marker) = drops.marker(
        case_id,
        parent_id,
        "BrowserCookieIncomplete",
        file_name,
        recovered,
    ) {
        artifacts.push(marker);
    }
    Ok(artifacts)
}

/// Parse a Firefox session-restore file (`sessionstore.jsonlz4` etc.): a
/// `mozLz40\0` header + LZ4-block-compressed JSON describing open windows/tabs.
/// Emits one BrowserSession record per tab (its current URL + title), showing
/// what was open when the session was saved.
///
/// Every path that returns an EMPTY tab list is either a genuine determination
/// or carries a [`file_incomplete_marker`] saying it is not one. The two genuine
/// determinations are a file too short to hold the container header and one
/// whose header is not `mozLz40\0`: neither is a session file at all. The rest —
/// over the byte ceiling, a source that under-delivered, a container declaring
/// an unusable decompressed size — used to return an empty list too, and "no
/// tabs were open" is a very different statement from "the open-tab list could
/// not be read".
///
/// The remaining two failures — an LZ4 block that will not decompress, and a
/// decompressed body that is not JSON — return `Err` instead of a marker, and
/// deliberately so: they reach the examiner as a `ModuleError` and an `error`
/// row in the processing log, which the generated report carries. What must
/// never happen is either of them resolving to `Ok(vec![])`, which the
/// orchestrator would record as a completed run over a profile with no open
/// tabs.
fn parse_firefox_session(
    ds: &dyn DataSource,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Result<Vec<Artifact>> {
    let size = ds.size();
    if size < 12 {
        return Ok(Vec::new());
    }
    let raw = match read_whole(ds, MAX_SESSION_BYTES) {
        Ok(bytes) => bytes,
        Err(short) => {
            let detail = match short.reason {
                IncompleteReason::CapReached => format!(
                    "the session file is {} bytes, past the {}-byte read ceiling, so no open \
                     tab was enumerated",
                    short.declared, MAX_SESSION_BYTES
                ),
                _ => format!(
                    "the source delivered {} of the {} bytes it declared, so the open-tab \
                     list could not be decompressed",
                    short.read, short.declared
                ),
            };
            return Ok(vec![file_incomplete_marker(
                case_id,
                parent_id,
                "BrowserSessionIncomplete",
                file_name,
                &short,
                &detail,
            )]);
        }
    };
    if &raw[0..8] != b"mozLz40\0" {
        warn!("Not a mozLz4 session file (bad magic)");
        return Ok(Vec::new());
    }
    let dec_size = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
    if dec_size == 0 || dec_size > MAX_SESSION_DECOMPRESSED_BYTES {
        // The magic says this IS a session file, so an empty return here would
        // assert the profile had no open tabs. It says nothing of the kind: we
        // refused to expand a container that declares an unusable size.
        let detail = format!(
            "the mozLz4 container declares {} decompressed bytes, outside the 1..={} range \
             this parser will expand, so no open tab was enumerated",
            dec_size, MAX_SESSION_DECOMPRESSED_BYTES
        );
        return Ok(vec![file_incomplete_marker(
            case_id,
            parent_id,
            "BrowserSessionIncomplete",
            file_name,
            &ShortFile {
                reason: IncompleteReason::UnresolvedStructure,
                declared: size,
                read: raw.len() as u64,
            },
            &detail,
        )]);
    }
    let json = lz4_flex::block::decompress(&raw[12..], dec_size)
        .context("Failed to LZ4-decompress session file")?;
    let doc: serde_json::Value =
        serde_json::from_slice(&json).context("Session file is not valid JSON")?;

    let mut artifacts = Vec::new();
    let windows = doc.get("windows").and_then(|w| w.as_array());
    for (wi, window) in windows.into_iter().flatten().enumerate() {
        let tabs = window.get("tabs").and_then(|t| t.as_array());
        for tab in tabs.into_iter().flatten() {
            let entries = tab.get("entries").and_then(|e| e.as_array());
            let Some(entries) = entries else { continue };
            if entries.is_empty() {
                continue;
            }
            // `index` is 1-based into entries; the current page is index-1.
            let idx = tab
                .get("index")
                .and_then(|i| i.as_u64())
                .map(|i| (i.saturating_sub(1)) as usize)
                .unwrap_or(entries.len() - 1)
                .min(entries.len() - 1);
            let entry = &entries[idx];
            let url = entry
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or_default();
            if url.is_empty() {
                continue;
            }
            let title = entry.get("title").and_then(|t| t.as_str()).unwrap_or("");
            let metadata = json!({
                "type": "BrowserSession",
                "subtype": "browser_session",
                "browser": "Firefox",
                "url": url,
                "title": title,
                "window": wi + 1,
                "name": format!("Open tab: {}", truncate_url(url, 80)),
            });
            artifacts.push(
                Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                    .with_parent(parent_id)
                    .with_subtype("browser_session"),
            );
        }
    }
    Ok(artifacts)
}

/// Parse Chrome/Edge `Login Data` saved logins (the `logins` table). The
/// username is stored in plaintext; only the password is OS-key encrypted. So
/// this recovers which accounts were saved for which sites, and when — a strong
/// investigative signal — without the passwords themselves.
///
/// `date_last_used` is optional: the oldest real store this parser was
/// validated against (meta.version 24, the 2021 Chromebook) predates it.
///
/// Ordered newest-created-first and bounded by `max_entries`, with a
/// `parse_incomplete` marker when the bound is reached: "no saved login for this
/// site" is a claim an examiner will make out loud, and it must not rest on a
/// listing that stopped early or on an arbitrary slice of the table.
fn parse_chrome_logins(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let has = table_exists(conn, "logins")?;
    if !has {
        warn!("Chrome Login Data missing 'logins' table");
        return Ok(artifacts);
    }
    let Some(logins) = resolved_plan(
        conn,
        &CHROME_LOGINS_SUPPORT,
        "logins",
        CHROME_LOGINS,
        CHROME_LOGINS_OPTIONAL,
        &mut artifacts,
        case_id,
        parent_id,
    )?
    else {
        return Ok(artifacts);
    };

    let sql = format!(
        "SELECT {origin}, {username}, {password}, {created}, {last_used}, {times} FROM logins \
         ORDER BY {created} DESC, {origin} ASC, {username} ASC LIMIT ?1",
        origin = col(&logins, "origin_url"),
        username = col(&logins, "username_value"),
        password = col(&logins, "password_value"),
        created = col(&logins, "date_created"),
        last_used = opt(&logins, "date_last_used", ""),
        times = col(&logins, "times_used"),
    );
    let walk = CappedWalk {
        sql: &sql,
        source_table: "logins",
        marker_type: "BrowserLoginIncomplete",
        what: "Chrome logins",
        max_entries,
    };
    artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
        let origin = row.get::<_, String>(0)?;
        let username = row.get::<_, String>(1).unwrap_or_default();
        let password = row.get::<_, Vec<u8>>(2).unwrap_or_default();
        let created = row.get::<_, i64>(3).unwrap_or(0);
        let last_used = row.get::<_, Option<i64>>(4).unwrap_or(None);
        let times = row.get::<_, i64>(5).unwrap_or(0);

        // Only claim encryption when a blob is actually stored. An empty
        // password_value means no saved secret at all (or one already
        // stripped), and "password_encrypted": true on such a row read as
        // "a password is here, sealed by the OS key" when nothing was
        // there (BUG-230).
        let metadata = json!({
            "type": "BrowserLogin",
            "subtype": "browser_login",
            "browser": "Chrome/Edge",
            "origin_url": origin,
            "username": username,
            "has_saved_password": !password.is_empty(),
            "password_encrypted": !password.is_empty(),
            "date_created": webkit_us_to_unix_secs(created),
            "last_used": last_used.and_then(webkit_us_to_unix_secs),
            "times_used": times,
            "name": format!("Login: {} ({})", truncate_url(&origin, 60), username),
        });
        Ok(vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(parent_id)
        .with_subtype("browser_login")])
    })?);
    Ok(artifacts)
}

/// Parse Chrome/Edge `Web Data` autofill (the `autofill` table): form field
/// name/value pairs the user typed, with use counts and first/last-used times
/// (Unix seconds). Plaintext — no OS-key encryption.
///
/// Ordered last-used-first and bounded by `max_entries`, with a
/// `parse_incomplete` marker when the bound is reached: the typed-value history
/// is often quoted as "the suspect never entered this address", and a silently
/// truncated slice of it would support that claim wrongly.
fn parse_chrome_autofill(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let has = table_exists(conn, "autofill")?;
    if !has {
        warn!("Chrome Web Data missing 'autofill' table");
        return Ok(artifacts);
    }
    let Some(autofill) = resolved_plan(
        conn,
        &CHROME_WEBDATA_SUPPORT,
        "autofill",
        CHROME_AUTOFILL,
        &[],
        &mut artifacts,
        case_id,
        parent_id,
    )?
    else {
        return Ok(artifacts);
    };

    let sql = format!(
        "SELECT {name}, {value}, {count}, {created}, {last_used} FROM autofill \
         ORDER BY {last_used} DESC, {name} ASC, {value} ASC LIMIT ?1",
        name = col(&autofill, "name"),
        value = col(&autofill, "value"),
        count = col(&autofill, "count"),
        created = col(&autofill, "date_created"),
        last_used = col(&autofill, "date_last_used"),
    );
    let walk = CappedWalk {
        sql: &sql,
        source_table: "autofill",
        marker_type: "BrowserAutofillIncomplete",
        what: "Chrome autofill",
        max_entries,
    };
    artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
        let field = row.get::<_, String>(0)?;
        let value = row.get::<_, String>(1)?;
        let count = row.get::<_, i64>(2).unwrap_or(0);
        let created = row.get::<_, i64>(3).unwrap_or(0);
        let last_used = row.get::<_, i64>(4).unwrap_or(0);

        let metadata = json!({
            "type": "BrowserAutofill",
            "subtype": "browser_autofill",
            "browser": "Chrome/Edge",
            "field_name": field,
            "value": value,
            "use_count": count,
            "first_used": if created > 0 { Some(created) } else { None },
            "last_used": if last_used > 0 { Some(last_used) } else { None },
            "name": format!("Autofill: {} = {}", field, truncate_url(&value, 60)),
        });
        Ok(vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(parent_id)
        .with_subtype("browser_autofill")])
    })?);
    Ok(artifacts)
}

/// Parse Firefox `formhistory.sqlite` (the `moz_formhistory` table): saved form
/// field values with use counts and first/last-used PRTime (Unix microseconds).
///
/// Ordered last-used-first and bounded by `max_entries`, flagged the same way as
/// the Chrome autofill walk.
fn parse_firefox_formhistory(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    max_entries: usize,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let has = table_exists(conn, "moz_formhistory")?;
    if !has {
        warn!("Firefox formhistory.sqlite missing 'moz_formhistory' table");
        return Ok(artifacts);
    }
    let Some(form) = resolved_plan(
        conn,
        &FIREFOX_FORMHISTORY_SUPPORT,
        "moz_formhistory",
        FIREFOX_FORMHISTORY,
        &[],
        &mut artifacts,
        case_id,
        parent_id,
    )?
    else {
        return Ok(artifacts);
    };

    let sql = format!(
        "SELECT {field}, {value}, {times}, {first}, {last} FROM moz_formhistory \
         ORDER BY {last} DESC, {field} ASC, {value} ASC LIMIT ?1",
        field = col(&form, "fieldname"),
        value = col(&form, "value"),
        times = col(&form, "timesUsed"),
        first = col(&form, "firstUsed"),
        last = col(&form, "lastUsed"),
    );
    let walk = CappedWalk {
        sql: &sql,
        source_table: "moz_formhistory",
        marker_type: "BrowserAutofillIncomplete",
        what: "Firefox form history",
        max_entries,
    };
    artifacts.extend(walk_capped_rows(conn, &walk, case_id, parent_id, |row| {
        let field = row.get::<_, String>(0)?;
        let value = row.get::<_, String>(1)?;
        let times = row.get::<_, i64>(2).unwrap_or(0);
        let first = row.get::<_, i64>(3).unwrap_or(0);
        let last = row.get::<_, i64>(4).unwrap_or(0);

        let metadata = json!({
            "type": "BrowserAutofill",
            "subtype": "browser_autofill",
            "browser": "Firefox",
            "field_name": field,
            "value": value,
            "use_count": times,
            "first_used": prtime_to_unix_secs(first),
            "last_used": prtime_to_unix_secs(last),
            "name": format!("Autofill: {} = {}", field, truncate_url(&value, 60)),
        });
        Ok(vec![Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(parent_id)
        .with_subtype("browser_autofill")])
    })?);
    Ok(artifacts)
}

/// Parse installed Chrome/Edge extensions from a `Preferences` /
/// `Secure Preferences` JSON file, reading `extensions.settings.<id>`. Returns
/// empty for any JSON that isn't a browser profile (no `extensions.settings`),
/// so the generic "Preferences" filename can't produce false positives.
///
/// That content check is only sound on bytes we actually hold. A file over the
/// read ceiling, or a source that under-delivered, used to take the same empty
/// return as "not a browser profile" — an inventory an examiner would read as
/// "no extensions were installed". Those now produce a
/// [`file_incomplete_marker`] instead, so the missing inventory is visible.
fn parse_browser_extensions(
    ds: &dyn DataSource,
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Vec<Artifact> {
    let size = ds.size();
    if size == 0 {
        return Vec::new();
    }
    let raw = match read_whole(ds, MAX_PREFS_BYTES) {
        Ok(bytes) => bytes,
        Err(short) => {
            let detail = match short.reason {
                IncompleteReason::CapReached => format!(
                    "the preferences file is {} bytes, past the {}-byte read ceiling, so the \
                     installed-extension inventory was not read",
                    short.declared, MAX_PREFS_BYTES
                ),
                _ => format!(
                    "the source delivered {} of the {} bytes it declared, so the \
                     installed-extension inventory could not be parsed",
                    short.read, short.declared
                ),
            };
            return vec![file_incomplete_marker(
                case_id,
                parent_id,
                "BrowserExtensionIncomplete",
                file_name,
                &short,
                &detail,
            )];
        }
    };

    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return Vec::new();
    };
    let Some(settings) = doc
        .pointer("/extensions/settings")
        .and_then(|v| v.as_object())
    else {
        return Vec::new(); // not a Chrome/Edge profile Preferences file
    };

    let mut out = Vec::new();
    for (id, entry) in settings {
        let manifest = entry.get("manifest");
        let ext_name = manifest
            .and_then(|m| m.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // Component extensions bundled with the browser have no useful manifest
        // name and are noise in an inventory; skip them.
        if ext_name.is_empty() && entry.get("location").and_then(|v| v.as_i64()) == Some(5) {
            continue;
        }

        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("BrowserExtension"));
        meta.insert("subtype".into(), json!("browser_extension"));
        meta.insert("browser".into(), json!("Chrome/Edge"));
        meta.insert("extension_id".into(), json!(id));
        if !ext_name.is_empty() {
            meta.insert("extension_name".into(), json!(ext_name));
        }
        if let Some(v) = manifest
            .and_then(|m| m.get("version"))
            .and_then(|v| v.as_str())
        {
            meta.insert("version".into(), json!(v));
        }
        if let Some(d) = manifest
            .and_then(|m| m.get("description"))
            .and_then(|v| v.as_str())
        {
            meta.insert("description".into(), json!(d));
        }
        let permissions: Vec<&str> = manifest
            .and_then(|m| m.get("permissions"))
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|p| p.as_str()).collect())
            .unwrap_or_default();
        if !permissions.is_empty() {
            meta.insert("permissions".into(), json!(permissions));
        }
        if let Some(s) = entry.get("state").and_then(|v| v.as_i64()) {
            meta.insert("enabled".into(), json!(s == 1));
        }
        if let Some(fw) = entry.get("from_webstore").and_then(|v| v.as_bool()) {
            meta.insert("from_webstore".into(), json!(fw));
        }
        if let Some(p) = entry.get("path").and_then(|v| v.as_str()) {
            meta.insert("install_path".into(), json!(p));
        }
        // install_time is WebKit microseconds held as a decimal string.
        if let Some(t) = entry
            .get("install_time")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(webkit_us_to_unix_secs)
        {
            meta.insert("install_time".into(), json!(t));
        }
        let display = if ext_name.is_empty() {
            format!("Browser extension: {}", id)
        } else {
            format!("Browser extension: {} ({})", ext_name, id)
        };
        meta.insert("name".into(), json!(display));

        out.push(
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::Value::Object(meta),
            )
            .with_parent(parent_id)
            .with_subtype("browser_extension"),
        );
    }
    out
}

// WebKit (Chrome/Safari, µs since 1601) and Firefox PRTime (µs since 1970)
// conversion lives in `seance_core::time` — imported at the top of this file.

// --- Transition type names ---

fn chrome_transition_name(transition: i64) -> &'static str {
    // Core transition type is in the lower 8 bits
    match transition & 0xFF {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "auto_toplevel",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        _ => "other",
    }
}

fn firefox_transition_name(visit_type: i64) -> &'static str {
    match visit_type {
        1 => "link",
        2 => "typed",
        3 => "bookmark",
        4 => "embed",
        5 => "redirect_permanent",
        6 => "redirect_temporary",
        7 => "download",
        8 => "framed_link",
        9 => "reload",
        _ => "other",
    }
}

/// Truncate a URL for display, keeping domain and start of path. Cuts on a
/// UTF-8 char boundary: URLs can carry raw multibyte characters (IRIs), and a
/// fixed byte slice would panic mid-character.
fn truncate_url(url: &str, max_len: usize) -> &str {
    if url.len() <= max_len {
        url
    } else {
        let mut end = max_len;
        while end > 0 && !url.is_char_boundary(end) {
            end -= 1;
        }
        &url[..end]
    }
}

/// Char-boundary-safe truncation for display strings (titles may be non-ASCII;
/// byte slicing could panic). Appends an ellipsis when truncated.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars).collect();
        out.push('\u{2026}');
        out
    }
}

/// Build a `TimelineEvent` artifact for a single web visit. Timestamps arrive as
/// Unix epoch seconds, which the timeline DB accepts directly.
fn make_visit_timeline_event(
    case_id: Uuid,
    parent_id: Uuid,
    browser: &str,
    url: &str,
    title: &str,
    visit_time_unix: i64,
) -> Artifact {
    let label = if !title.is_empty() { title } else { url };
    Artifact::new(
        case_id,
        ArtifactType::TimelineEvent,
        None,
        json!({
            "timestamp": visit_time_unix,
            "timestamp_desc": "Web Visit",
            "source_module": "plugin.browsers.history_parser",
            "short_desc": format!("Web visit: {}", truncate_chars(label, 100)),
            "browser": browser,
            "url": url,
            "title": title,
        }),
    )
    .with_parent(parent_id)
}

impl ForensicsModule for BrowserHistoryParser {
    fn id(&self) -> &str {
        "plugin.browsers.history_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // A `ParsedRecord` is read only when it is a shadow-copy prior version
        // (HUNT-277); every other parsed record returns before its data is touched.
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl BrowserHistoryParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // A prior version is named `<file> [shadow copy <time>]`; the name tests below
        // decide by the file's original name.
        let name = seance_core::shadow_copy::original_name(artifact).unwrap_or_default();

        // Firefox session restore is LZ4-compressed JSON, not SQLite — handle it
        // separately before the SQLite path.
        if is_firefox_session(name) {
            let Some(ds) = artifact.data.as_ref() else {
                return Ok(vec![unread_file_marker(
                    artifact.case_id,
                    artifact.id,
                    "BrowserSessionIncomplete",
                    name,
                    "no data source was attached to this session file, so no open tab was \
                     enumerated",
                )]);
            };
            return parse_firefox_session(ds.as_ref(), artifact.case_id, artifact.id, name)
                .map_err(|e| ModuleError::ParsingError(e.to_string()));
        }

        // Safari's own cookie jar is Apple's binary `cook` format, not
        // SQLite — handle it separately before the SQLite path, the same way
        // the Firefox session store is handled above.
        if is_safari_binarycookies(name) {
            let Some(ds) = artifact.data.as_ref() else {
                return Ok(vec![unread_file_marker(
                    artifact.case_id,
                    artifact.id,
                    "BrowserCookieIncomplete",
                    name,
                    "no data source was attached to this cookie jar, so no Safari cookie was \
                     recovered from it",
                )]);
            };
            return parse_safari_binarycookies(ds.as_ref(), artifact.case_id, artifact.id, name)
                .map_err(|e| ModuleError::ParsingError(e.to_string()));
        }

        // Chrome/Edge extensions live in the Preferences / Secure Preferences
        // JSON, not SQLite. parse_browser_extensions content-verifies the file, so
        // a non-profile "Preferences" simply yields nothing.
        if is_browser_preferences(name) {
            let Some(ds) = artifact.data.as_ref() else {
                return Ok(vec![unread_file_marker(
                    artifact.case_id,
                    artifact.id,
                    "BrowserExtensionIncomplete",
                    name,
                    "no data source was attached to this preferences file, so the \
                     installed-extension inventory was not read",
                )]);
            };
            return Ok(parse_browser_extensions(
                ds.as_ref(),
                artifact.case_id,
                artifact.id,
                name,
            ));
        }

        let (browser_type, kind) = if let Some(b) = identify_browser(name) {
            (b, DbKind::History)
        } else if let Some(b) = identify_cookies(name) {
            (b, DbKind::Cookies)
        } else if let Some(b) = identify_autofill(name) {
            (b, DbKind::Autofill)
        } else if let Some(b) = identify_logins(name) {
            (b, DbKind::Logins)
        } else {
            return Ok(Vec::new());
        };

        info!(
            "BrowserHistoryParser processing {} {}: {}",
            browser_type,
            kind.label(),
            name
        );

        // If no data source, produce an identification-only artifact
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => {
                info!(
                    "No data source for {}, producing identification artifact only",
                    name
                );
                // NOT `BrowserHistory`: `seance_db` groups records by
                // `metadata.$.type`, so a record typed as the thing it failed
                // to produce is counted as one of them. `walk.rs` states the
                // rule for its own markers; these four broke it.
                let detail = format!(
                    concat!(
                        "this file was identified as a {} history database and was not read: ",
                        "the artifact carried no data source, so no visit was recovered from it ",
                        "and none is claimed"
                    ),
                    browser_type
                );
                let metadata = json!({
                    "type": "BrowserHistoryParseStatus",
                    "subtype": "browser_history_status",
                    "browser": browser_type,
                    "file_name": name,
                    "status": "Identified",
                    "content_incomplete": true,
                    "content_incomplete_reason": "unvalidated",
                    "content_incomplete_detail": detail.clone(),
                    "detail": detail,
                    "name": format!("{} History Database (not parsed - no data)", browser_type),
                });
                let id_artifact =
                    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(artifact.id);
                return Ok(vec![id_artifact]);
            }
        };

        // Extract to temp file for rusqlite
        let temp = TempDb::spill(data_source.as_ref(), "browser", MAX_DB_BYTES)
            .map_err(|e| ModuleError::ParsingError(format!("Failed to extract DB: {}", e)))?;

        let result = (|| -> Result<Vec<Artifact>> {
            let conn = temp.open().context("Failed to open browser database")?;

            let mut artifacts = match (browser_type, kind) {
                ("Chrome/Edge", DbKind::History) => {
                    parse_chrome(&conn, artifact.case_id, artifact.id, MAX_HISTORY_ENTRIES)
                }
                ("Firefox", DbKind::History) => {
                    parse_firefox(&conn, artifact.case_id, artifact.id, MAX_HISTORY_ENTRIES)
                }
                ("Safari", DbKind::History) => {
                    parse_safari(&conn, artifact.case_id, artifact.id, MAX_HISTORY_ENTRIES)
                }
                ("Chrome/Edge", DbKind::Cookies) => {
                    parse_chrome_cookies(&conn, artifact.case_id, artifact.id, MAX_HISTORY_ENTRIES)
                }
                ("Firefox", DbKind::Cookies) => {
                    parse_firefox_cookies(&conn, artifact.case_id, artifact.id, MAX_HISTORY_ENTRIES)
                }
                ("Chrome/Edge", DbKind::Autofill) => {
                    parse_chrome_autofill(&conn, artifact.case_id, artifact.id, MAX_HISTORY_ENTRIES)
                }
                ("Firefox", DbKind::Autofill) => parse_firefox_formhistory(
                    &conn,
                    artifact.case_id,
                    artifact.id,
                    MAX_HISTORY_ENTRIES,
                ),
                ("Chrome/Edge", DbKind::Logins) => {
                    parse_chrome_logins(&conn, artifact.case_id, artifact.id, MAX_HISTORY_ENTRIES)
                }
                _ => Ok(Vec::new()),
            }?;
            // The store's schema version against what this parser was
            // validated for, after the walks so the marker follows the records
            // it qualifies.
            if let Some(support) = support_for(browser_type, kind) {
                artifacts.extend(version_marker(
                    &conn,
                    browser_type,
                    support,
                    artifact.case_id,
                    artifact.id,
                ));
            }
            Ok(artifacts)
        })();

        match result {
            Ok(mut artifacts) => {
                // The spill knows whether the database file itself arrived whole
                // (over `MAX_DB_BYTES`, or a source that could not deliver its
                // declared bytes). SQLite opens a truncated file happily and
                // answers from the pages it can reach, so without this a partial
                // profile parses as a complete browsing history.
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                info!(
                    "BrowserHistoryParser extracted {} records from {} ({})",
                    artifacts.len(),
                    name,
                    browser_type
                );
                Ok(artifacts)
            }
            Err(e) => {
                warn!("Failed to parse {} history ({}): {}", browser_type, name, e);
                // Return identification artifact on parse failure
                let detail = format!(
                    concat!(
                        "this file was identified as a {} history database and could not be ",
                        "parsed, so no visit was recovered from it: {}"
                    ),
                    browser_type, e
                );
                let metadata = json!({
                    "type": "BrowserHistoryParseStatus",
                    "subtype": "browser_history_status",
                    "browser": browser_type,
                    "file_name": name,
                    "status": "ParseFailed",
                    "error": e.to_string(),
                    "content_incomplete": true,
                    "content_incomplete_reason": "unresolved_structure",
                    "content_incomplete_detail": detail.clone(),
                    "detail": detail,
                    "name": format!("{} History Database (parse failed)", browser_type),
                });
                let mut out = vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    metadata,
                )
                .with_parent(artifact.id)];
                // A database staged short is the likeliest REASON the parse
                // failed, and "SQLite could not read this" without "because we
                // only hold part of the file" invites the wrong conclusion —
                // that the evidence itself is corrupt.
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
                Ok(out)
            }
        }
    }
}
