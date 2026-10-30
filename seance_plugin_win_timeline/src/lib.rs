#![forbid(unsafe_code)]
//! Schema-aware parser for the **Windows 10/11 Timeline** database
//! (`ActivitiesCache.db`, the artifact Eric Zimmerman's *WxTCmd* targets).
//!
//! As a user works, the *ConnectedDevicesPlatform* (CDP) service records each
//! meaningful interaction — an app launched, a document opened, a web page
//! viewed, a clipboard copy — into a per-user SQLite database. This plugin turns
//! the opaque `Activity` / `ActivityOperation` / `Activity_PackageId` rows into
//! structured, timeline-integrated `WindowsTimelineActivity` records the way
//! `seance_plugin_ios_artifacts` did for `voicemail.db` / `Photos.sqlite`.
//!
//! It self-selects by basename (`activitiescache.db`) plus SQLite magic, then
//! **structurally verifies** the schema (the `Activity` / `Activity_PackageId`
//! tables and the signature columns) before parsing, probes columns at runtime,
//! and never panics on an unexpected schema. Every timestamp is fail-closed: a
//! non-positive value is omitted, never emitted as `1970-01-01`.

use base64::Engine;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Row};
use seance_core::io::{is_sqlite_header, read_full};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    guid::format_guid,
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{probe_columns, probe_table, table_columns, Presence, TempDb};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use uuid::Uuid;

const MODULE_ID: &str = "plugin.windows.timeline_activity";

/// Hostile-input ceiling. Timeline DBs are normally single-digit MB; 2 GiB is a
/// ceiling, not an expectation (matches the SRUM precedent).
const MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Cap on decoded clipboard text stored in a record (a hostile blob must not
/// balloon a row).
const CLIPBOARD_CAP: usize = 8 * 1024;
/// Cap on the raw `AppId` JSON kept for provenance.
const APPID_RAW_CAP: usize = 64 * 1024;

fn basename(name: &str) -> String {
    name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase()
}

/// Gate an artifact by basename + SQLite magic, spill to a temp file, hand a
/// read-only connection to `f`, then clean up (RAII, panic-safe). Mirrors the
/// `with_db` front end used by `seance_plugin_ios_artifacts`.
///
/// The spill goes through [`TempDb::spill`], which compares what the source
/// delivered against what it declared. SQLite opens a truncated `ActivitiesCache.db`
/// and answers happily from the pages it can still reach, so a partial staging
/// yields a partial activity list that is otherwise indistinguishable from a
/// complete one. Everything `f` produces is therefore stamped with
/// `content_incomplete` / `content_incomplete_reason` (and
/// `wal_incomplete_reason` when the uncheckpointed log could not be staged),
/// plus one `parse_incomplete` marker so the fact survives even when the
/// truncation left no parsable rows at all (B3-011).
///
/// What an examiner learns: whether the activities on screen are the whole
/// Timeline. A wrong answer here reads as "the user did not open that document",
/// which the evidence does not support.
fn with_db<F>(artifact: &Artifact, names: &[&str], tag: &str, f: F) -> Vec<Artifact>
where
    F: FnOnce(&Connection, Uuid, Uuid) -> Vec<Artifact>,
{
    // A prior version's `name` carries the shadow-copy label.
    let name = seance_core::shadow_copy::original_name(artifact).unwrap_or("");
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
    // would file a real Timeline database as "not SQLite".
    let mut head = [0u8; 16];
    let n = read_full(data.as_ref(), 0, &mut head);
    if !is_sqlite_header(&head[..n]) {
        return Vec::new();
    }
    // `spill` stages the `-wal` sibling alongside the database — a live
    // ActivitiesCache routinely holds its newest activities in an
    // uncheckpointed WAL, and the main file alone silently omits them
    // (BUG-256) — and records whether the database itself was staged in full.
    let temp = match TempDb::spill(data.as_ref(), &format!("wintl_{tag}"), MAX_DB_BYTES) {
        Ok(t) => t,
        Err(e) => {
            // The basename matched and the file really is SQLite: it is a
            // Timeline database that could not be staged. Returning nothing here
            // is read as "this user had no activity history".
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
        Ok(conn) => f(&conn, artifact.case_id, artifact.id),
        Err(e) => vec![db_unusable_artifact(
            artifact.case_id,
            artifact.id,
            name,
            "staged database could not be opened",
            &e.to_string(),
        )],
    };
    // Stamp whenever the staging was short, even if nothing parsed: "the
    // database stopped being readable at byte N" and "this user had no
    // activity history" must not render identically.
    temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut out);
    out
}

/// The record that says a recognised Timeline database could not be read at all.
///
/// Mirrors the `parse_incomplete` marker `TempDb::stamp_incompleteness` appends,
/// for the failures that happen before any row can be read.
fn db_unusable_artifact(
    case_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
    what: &str,
    detail: &str,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("WindowsTimelineParseStatus"));
    meta.insert("subtype".into(), json!("parse_incomplete"));
    meta.insert("status".into(), json!("DatabaseUnreadable"));
    meta.insert("file_name".into(), json!(file_name));
    meta.insert("content_incomplete".into(), json!(true));
    meta.insert(
        "content_incomplete_reason".into(),
        json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
    );
    meta.insert("inventory_incomplete".into(), json!(true));
    meta.insert(
        "inventory_incomplete_reason".into(),
        json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
    );
    meta.insert("records_recovered".into(), json!(0));
    meta.insert("detail".into(), json!(format!("{what}: {detail}")));
    meta.insert(
        "name".into(),
        json!(format!("{file_name}: Timeline unreadable — {what}")),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype("parse_incomplete")
}

fn has_table(conn: &Connection, table: &str) -> bool {
    // Delegates so views count as present. A schema that exposes its rows
    // through a compatibility view -- recent `msgstore.db` generations keep
    // `messages` as one over the `message` table -- answered `type='table'`
    // with "no such table", and the walk that depends on it produced nothing
    // while the case read as a device with no records of this kind.
    matches!(probe_table(conn, table), Presence::Present)
}

// --- tolerant cell readers ---------------------------------------------------

/// Text / Integer / Real → non-empty `String`.
fn cstr(r: &Row, idx: usize) -> Option<String> {
    seance_sqlite_util::row_text_present(r, idx)
}

/// Integer / Real → `i64`.
fn cint(r: &Row, idx: usize) -> Option<i64> {
    seance_sqlite_util::row_i64(r, idx)
}

/// A BLOB (or TEXT) column holding UTF-8 (e.g. `Payload`, `AppId`,
/// `ClipboardPayload`) → the decoded string. A non-UTF-8 BLOB yields `None`.
fn cblob_utf8(r: &Row, idx: usize) -> Option<String> {
    match r.get_ref(idx).ok()? {
        ValueRef::Text(t) | ValueRef::Blob(t) => std::str::from_utf8(t).ok().map(str::to_string),
        _ => None,
    }
    .filter(|s| !s.is_empty())
}

/// The `Id` column: a TEXT GUID is used as-is; a 16-byte BLOB is formatted as a
/// .NET-layout GUID string (`seance_core::guid::format_guid` — the same
/// Microsoft mixed-endian convention the VSS catalog uses); any other UTF-8 BLOB
/// is used verbatim.
fn cid(r: &Row, idx: usize) -> Option<String> {
    match r.get_ref(idx).ok()? {
        ValueRef::Text(t) => std::str::from_utf8(t).ok().map(str::to_string),
        ValueRef::Blob(b) if b.len() == 16 => <&[u8; 16]>::try_from(b).ok().map(format_guid),
        ValueRef::Blob(b) => std::str::from_utf8(b).ok().map(str::to_string),
        _ => None,
    }
    .filter(|s| !s.is_empty())
}

fn iso8601(unix: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix, 0).map(|dt| dt.to_rfc3339())
}

/// A positive Unix-seconds timestamp, or `None`. This is the fail-closed guard:
/// a non-positive stored value is omitted, never surfaced as the 1970 epoch.
fn pos_time(v: Option<i64>) -> Option<i64> {
    v.filter(|&t| t > 0)
}

// --- Known-Folder GUID rewrite (§2.5) ---------------------------------------

/// A small map of the common Windows Known-Folder GUIDs that prefix an
/// `x_exe_path` `AppId`, so `{6D809377-...}\...\winword.exe` displays as
/// `%ProgramFiles%\...\winword.exe`. Unknown GUIDs are left verbatim (never
/// guessed). Keys are upper-cased, brace-less.
fn known_folder(guid_upper: &str) -> Option<&'static str> {
    Some(match guid_upper {
        "6D809377-6AF0-444B-8957-A3773F02200E" => "%ProgramFiles%",
        "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E" => "%ProgramFiles(x86)%",
        "F38BF404-1D43-42F2-9305-67DE0B28FC23" => "%WinDir%",
        "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7" => "%WinDir%\\System32",
        "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27" => "%WinDir%\\System32", // SystemX86
        "5E6C858F-0E22-4760-9AFE-EA3317B67173" => "%UserProfile%",
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" => "%LocalAppData%",
        "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D" => "%AppData%",
        "A520A1A4-1780-4FF6-BD18-167343C5AF16" => "%LocalAppDataLow%",
        "B4BFCC3A-DB2C-424C-B029-7FE99A87C641" => "Desktop",
        "FDD39AD0-238F-46AF-ADB4-6C85480369C7" => "Documents",
        "374DE290-123F-4565-9164-39C4925E467B" => "Downloads",
        "4BD8D571-6D19-48D3-BE97-422220080E43" => "Music",
        "33E28130-4E1E-4676-835A-98395C3BC3BB" => "Pictures",
        "18989B1D-99B5-455B-841C-AB7C74E4DDFC" => "Videos",
        "A63293E8-664E-48DB-A079-DF759E0509F7" => "Templates",
        "0762D272-C50A-4BB0-A382-697DCD729B80" => "Users",
        "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97" => "%ProgramData%",
        "DE974D24-D9C6-4D3E-BF91-F4455120B917" => "%ProgramFiles%\\Common Files",
        "F7F1ED05-9F6D-47A2-AAAE-29D317C6F066" => "%ProgramFiles%\\Common Files",
        _ => return None,
    })
}

/// Rewrite a leading `{GUID}` Known-Folder prefix in an executable path.
fn rewrite_known_folder(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('{') {
        if let Some(end) = rest.find('}') {
            let guid = &rest[..end];
            if let Some(name) = known_folder(&guid.to_ascii_uppercase()) {
                return format!("{name}{}", &rest[end + 1..]);
            }
        }
    }
    path.to_string()
}

// --- AppId resolution (§2.5) ------------------------------------------------

/// One resolved application identity from the `AppId` JSON array.
struct AppIdEntry {
    application: String,
    platform: String,
}

/// Parse the `AppId` JSON array (`[{"application":"...","platform":"..."}]`)
/// into entries. A non-array / malformed value yields an empty vec.
fn parse_app_ids(raw: &str) -> Vec<AppIdEntry> {
    let mut out = Vec::new();
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw) {
        for it in items {
            let application = it.get("application").and_then(|v| v.as_str());
            let platform = it.get("platform").and_then(|v| v.as_str());
            if let (Some(app), Some(plat)) = (application, platform) {
                if !app.is_empty() {
                    out.push(AppIdEntry {
                        application: app.to_string(),
                        platform: plat.to_string(),
                    });
                }
            }
        }
    }
    out
}

/// Resolve the real executable from AppId entries (falling back to the
/// package-map entries), matching WxTCmd's preference order: a real Win32 path,
/// else an `x_exe_path` (Known-Folder-rewritten), else the universal id, else the
/// first entry.
fn resolve_executable(app_ids: &[AppIdEntry], packages: &[AppIdEntry]) -> Option<String> {
    let pick = |entries: &[AppIdEntry], plat: &str| -> Option<String> {
        entries
            .iter()
            .find(|e| e.platform.eq_ignore_ascii_case(plat))
            .map(|e| rewrite_known_folder(&e.application))
    };
    for source in [app_ids, packages] {
        if let Some(p) = pick(source, "windows_win32") {
            return Some(p);
        }
        if let Some(p) = pick(source, "x_exe_path") {
            return Some(p);
        }
    }
    pick(app_ids, "windows_universal")
        .or_else(|| {
            app_ids
                .first()
                .map(|e| rewrite_known_folder(&e.application))
        })
        .or_else(|| {
            packages
                .first()
                .map(|e| rewrite_known_folder(&e.application))
        })
}

// --- ActivityType labels (documentation/WINDOWS_DESIGN.md, Windows Timeline section, advisory) ---

fn activity_type_label(t: Option<i64>) -> String {
    match t {
        Some(2) => "Notification".into(),
        Some(3) => "Mobile backup / Azure auth".into(),
        Some(5) => "Open app / file / webpage".into(),
        Some(6) => "App in focus".into(),
        Some(10) => "Clipboard".into(),
        Some(11) | Some(12) | Some(15) => "System operation".into(),
        Some(16) => "Copy/paste".into(),
        Some(n) => format!("Type {n}"),
        None => "Unknown".into(),
    }
}

fn is_clipboard_type(t: Option<i64>) -> bool {
    matches!(t, Some(10) | Some(16))
}

// --- Payload decode (§2.4) --------------------------------------------------

#[derive(Default)]
struct PayloadData {
    display_text: Option<String>,
    app_display_name: Option<String>,
    description: Option<String>,
    activation_uri: Option<String>,
    content_uri: Option<String>,
    reporting_app: Option<String>,
    active_duration_seconds: Option<i64>,
    user_timezone: Option<String>,
    device_platform: Option<String>,
    payload_binary: bool,
}

/// Decode the `Payload` BLOB (UTF-8 JSON). A non-JSON payload sets
/// `payload_binary` and leaves every decoded key `None` (never fabricated).
fn decode_payload(raw: Option<&str>) -> PayloadData {
    let mut p = PayloadData::default();
    let Some(raw) = raw else {
        return p;
    };
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        p.payload_binary = true;
        return p;
    };
    let Value::Object(_) = &v else {
        p.payload_binary = true;
        return p;
    };
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    p.display_text = s("displayText");
    p.app_display_name = s("appDisplayName");
    p.description = s("description");
    p.activation_uri = s("activationUri");
    p.content_uri = s("contentUri").map(|u| percent_decode(&u));
    p.reporting_app = s("reportingApp");
    p.user_timezone = s("userTimezone");
    p.device_platform = s("devicePlatform");
    // activeDurationSeconds may be a number or a numeric string.
    p.active_duration_seconds = v
        .get("activeDurationSeconds")
        .and_then(|x| {
            x.as_i64()
                .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
        })
        .filter(|&d| d >= 0);
    p
}

/// Minimal, allocation-safe percent-decoder for `contentUri`. Invalid escapes or
/// non-UTF-8 results fall back to the original string.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// --- ClipboardPayload decode (§2.7) -----------------------------------------

struct ClipboardData {
    text: Option<String>,
    format: Option<String>,
    bytes_len: usize,
    /// The decoded text was longer than [`CLIPBOARD_CAP`] and `text` holds only
    /// its beginning.
    ///
    /// Forensic meaning: clipboard contents are often the evidence itself — a
    /// pasted password, an exfiltrated document, a copied address. A silently
    /// shortened capture reads as the whole thing an examiner would quote in a
    /// report, so the shortfall has to travel with the record.
    text_truncated: bool,
}

/// Decode the `ClipboardPayload` BLOB: `[{"content":"<base64>","format":"Text"}]`.
/// A `Text` entry is base64-decoded to UTF-8 and length-capped; a non-`Text`
/// format (e.g. a bitmap) records only the format and decoded byte length, never
/// fabricated text.
fn decode_clipboard(raw: Option<&str>) -> Option<ClipboardData> {
    let raw = raw?;
    let arr = match serde_json::from_str::<Value>(raw).ok()? {
        Value::Array(a) => a,
        _ => return None,
    };
    let entry = arr.into_iter().find(|e| e.get("content").is_some())?;
    let content = entry.get("content").and_then(|v| v.as_str())?;
    let format = entry
        .get("format")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let decoded = base64::engine::general_purpose::STANDARD.decode(content);
    let is_text = format
        .as_deref()
        .map(|f| f.eq_ignore_ascii_case("Text"))
        .unwrap_or(false);
    match decoded {
        Ok(bytes) if is_text => {
            let bytes_len = bytes.len();
            let mut text_truncated = false;
            let text = String::from_utf8(bytes).ok().map(|mut t| {
                if t.len() > CLIPBOARD_CAP {
                    // Cut on a char boundary so the kept prefix stays valid
                    // UTF-8 rather than panicking mid-code-point.
                    let mut cut = CLIPBOARD_CAP;
                    while cut > 0 && !t.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    t.truncate(cut);
                    text_truncated = true;
                }
                t
            });
            Some(ClipboardData {
                text,
                format,
                bytes_len,
                text_truncated,
            })
        }
        Ok(bytes) => Some(ClipboardData {
            text: None,
            text_truncated: false,
            format,
            bytes_len: bytes.len(),
        }),
        Err(_) => Some(ClipboardData {
            text: None,
            text_truncated: false,
            format,
            bytes_len: content.len(),
        }),
    }
}

// --- column-tolerant projection ---------------------------------------------

/// Build a bracket-quoted `SELECT` projection over exactly the `wanted` columns
/// that exist in `table`, plus a name → result-index map so a build variant
/// missing a column (e.g. `ClipboardPayload`) still parses.
fn projection(
    cols: &std::collections::HashSet<String>,
    wanted: &[&'static str],
) -> (String, HashMap<&'static str, usize>) {
    let mut selected = Vec::new();
    let mut idx = HashMap::new();
    for &w in wanted {
        if cols.contains(&w.to_ascii_lowercase()) {
            idx.insert(w, selected.len());
            selected.push(format!("[{w}]"));
        }
    }
    (selected.join(", "), idx)
}

/// The `Activity` / `ActivityOperation` columns we consume, in projection order.
const ACTIVITY_COLUMNS: &[&str] = &[
    "Id",
    "AppId",
    "ActivityType",
    "ActivityStatus",
    "Group",
    "Payload",
    "ClipboardPayload",
    "StartTime",
    "EndTime",
    "LastModifiedTime",
    "ExpirationTime",
    "LastModifiedOnClient",
    "CreatedInCloud",
    "IsLocalOnly",
    "PlatformDeviceId",
    "OperationType",
    "OperationOrder",
];

/// The signature columns that must be present on `Activity` for a DB to be a
/// genuine Timeline cache. `ClipboardPayload` / `CreatedInCloud` are build-
/// dependent and are deliberately *not* required (they were added in 1903).
const SIGNATURE_COLUMNS: &[&str] = &["ActivityType", "Payload", "StartTime"];

fn get_i(r: &Row, idx: &HashMap<&str, usize>, name: &str) -> Option<i64> {
    idx.get(name).and_then(|&i| cint(r, i))
}
fn get_s(r: &Row, idx: &HashMap<&str, usize>, name: &str) -> Option<String> {
    idx.get(name).and_then(|&i| cstr(r, i))
}
fn get_blob(r: &Row, idx: &HashMap<&str, usize>, name: &str) -> Option<String> {
    idx.get(name).and_then(|&i| cblob_utf8(r, i))
}

// --- the module -------------------------------------------------------------

/// Parser for `ActivitiesCache.db` (the Windows 10/11 Timeline / Activity
/// History). Emits one `WindowsTimelineActivity` `ParsedRecord` plus one
/// `TimelineEvent` per activity.
pub struct ActivitiesCacheParser;

impl ForensicsModule for ActivitiesCacheParser {
    fn id(&self) -> &str {
        MODULE_ID
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }
    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(
            artifact,
            |a| -> Result<Vec<Artifact>, ModuleError> {
                Ok(with_db(a, &["activitiescache.db"], "act", parse_timeline))
            },
        )
    }
}

/// Structural verify + parse. Any deviation from the expected schema returns an
/// empty vec rather than an error.
fn parse_timeline(conn: &Connection, case: Uuid, parent: Uuid) -> Vec<Artifact> {
    // Stage-2 structural gate: the signature tables must exist...
    //
    // Three answers, not two (B8-048). `has_table` folded
    // `Presence::Undetermined` — the catalogue would not answer — into `false`,
    // so an `ActivitiesCache.db` that opened and could not be catalogued
    // returned an empty vec with no status record. That reads as a user with no
    // activity history, which is a claim about the custodian this tool never
    // established. Only `Absent` is a finding; `Undetermined` is damage.
    const FILE: &str = "ActivitiesCache.db";
    for table in ["Activity", "Activity_PackageId"] {
        match probe_table(conn, table) {
            Presence::Present => {}
            // The catalogue ANSWERED and the table is not there: this is not a
            // Windows Timeline schema, and silence is the right answer.
            Presence::Absent => return Vec::new(),
            Presence::Undetermined(why) => {
                return vec![db_unusable_artifact(
                    case,
                    parent,
                    FILE,
                    "the schema catalogue would not answer",
                    &format!("the `{table}` table could not be looked for: {why}"),
                )]
            }
        }
    }
    // ...and `Activity` must carry the signature columns. `probe_columns`, not
    // `table_columns`: the latter answers an empty set when the PRAGMA fails,
    // and an empty set fails every signature check below, so a damaged store
    // produced the same silence as a schema that was never Timeline's.
    let activity_cols = match probe_columns(conn, "Activity") {
        Ok(cols) => cols,
        Err(why) => {
            return vec![db_unusable_artifact(
                case,
                parent,
                FILE,
                "the column list would not read",
                &format!("`Activity` is present and its columns could not be listed: {why}"),
            )]
        }
    };
    if !SIGNATURE_COLUMNS
        .iter()
        .all(|c| activity_cols.contains(&c.to_ascii_lowercase()))
    {
        return Vec::new();
    }

    let mut walk = WalkGaps::default();
    let packages = build_package_map(conn, &mut walk);

    let mut out = Vec::new();
    parse_activity_table(
        conn,
        "Activity",
        &activity_cols,
        &packages,
        case,
        parent,
        &mut out,
        &mut walk,
    );
    if has_table(conn, "ActivityOperation") {
        let op_cols = table_columns(conn, "ActivityOperation");
        parse_activity_table(
            conn,
            "ActivityOperation",
            &op_cols,
            &packages,
            case,
            parent,
            &mut out,
            &mut walk,
        );
    }
    walk.stamp(case, parent, &mut out);
    out
}

/// `ActivityId → [(platform, packageName)]` from `Activity_PackageId`, keyed by
/// the same GUID rendering used for `Activity.Id` so the join aligns.
fn build_package_map(conn: &Connection, walk: &mut WalkGaps) -> HashMap<String, Vec<AppIdEntry>> {
    let mut map: HashMap<String, Vec<AppIdEntry>> = HashMap::new();
    let Ok(mut stmt) =
        conn.prepare("SELECT [ActivityId], [Platform], [PackageName] FROM Activity_PackageId")
    else {
        walk.package_query_failed = true;
        return map;
    };
    let Ok(rows) = stmt.query_map([], |r| Ok((cid(r, 0), cstr(r, 1), cstr(r, 2)))) else {
        walk.package_query_failed = true;
        return map;
    };
    for row in rows {
        // A dropped package row costs an activity its app attribution, so it is
        // counted rather than discarded by `flatten`.
        let Ok((aid, platform, name)) = row else {
            walk.package_row_errors += 1;
            continue;
        };
        if let (Some(aid), Some(platform), Some(name)) = (aid, platform, name) {
            map.entry(aid).or_default().push(AppIdEntry {
                application: name,
                platform,
            });
        }
    }
    map
}

/// What the activity walk could not read.
///
/// Windows Timeline answers "what did this user open, and when". A dropped row
/// removes an activity from that answer, and a dropped package row removes the
/// application name from one that stays. Neither may pass unremarked.
#[derive(Default)]
struct WalkGaps {
    /// Rows of `Activity` / `ActivityOperation` that would not decode.
    activity_row_errors: u64,
    /// Rows of `Activity_PackageId` that would not decode.
    package_row_errors: u64,
    /// An activity table could not be prepared or queried at all.
    activity_query_failed: bool,
    /// The package map could not be built.
    package_query_failed: bool,
}

/// Add an incompleteness reason without erasing one an earlier stage stamped.
///
/// Two stages can each find the same record short — a clipboard blob capped
/// while decoding it, and a table walk that lost rows around it. Whichever
/// stamps second must not hide what the first found.
fn add_incomplete_reason(map: &mut Map<String, Value>, reason: &str) {
    map.insert("content_incomplete".into(), json!(true));
    let merged = match map
        .get("content_incomplete_reason")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(existing) if existing.split('+').any(|r| r == reason) => existing.to_string(),
        Some(existing) => format!("{}+{}", existing, reason),
        None => reason.to_string(),
    };
    map.insert("content_incomplete_reason".into(), json!(merged));
}

impl WalkGaps {
    fn is_clean(&self) -> bool {
        self.activity_row_errors == 0
            && self.package_row_errors == 0
            && !self.activity_query_failed
            && !self.package_query_failed
    }

    fn reason(&self) -> &'static str {
        seance_core::io::IncompleteReason::UnresolvedStructure.as_str()
    }

    /// Stamp the gaps onto every record the walk produced, and append one
    /// marker so the fact survives even when nothing decoded.
    fn stamp(&self, case: Uuid, parent: Uuid, out: &mut Vec<Artifact>) {
        if self.is_clean() {
            return;
        }
        for a in out.iter_mut() {
            let Some(map) = a.metadata.as_object_mut() else {
                continue;
            };
            // Merged, never overwritten. `build_record` already stamps
            // `cap_reached` on a record whose clipboard text or raw `AppId` was
            // truncated to its cap; a plain insert here replaced that with the
            // walk's reason, so an examiner was told the row was structurally
            // incomplete and never told its clipboard text had been cut.
            add_incomplete_reason(map, self.reason());
            map.insert("inventory_incomplete".into(), json!(true));
            map.insert("inventory_incomplete_reason".into(), json!(self.reason()));
        }
        let detail = format!(
            "{} activity rows and {} package-id rows could not be decoded\
             {}{}; the activities listed are a floor, not the user's whole Timeline",
            self.activity_row_errors,
            self.package_row_errors,
            if self.activity_query_failed {
                "; an activity table could not be queried"
            } else {
                ""
            },
            if self.package_query_failed {
                "; the application-name map could not be built"
            } else {
                ""
            },
        );
        let mut meta = Map::new();
        meta.insert("type".into(), json!("WindowsTimelineParseStatus"));
        meta.insert("subtype".into(), json!("parse_incomplete"));
        meta.insert("status".into(), json!("RowsNotDecoded"));
        meta.insert("content_incomplete".into(), json!(true));
        meta.insert("content_incomplete_reason".into(), json!(self.reason()));
        meta.insert("inventory_incomplete".into(), json!(true));
        meta.insert("inventory_incomplete_reason".into(), json!(self.reason()));
        meta.insert(
            "activity_row_errors".into(),
            json!(self.activity_row_errors),
        );
        meta.insert("package_row_errors".into(), json!(self.package_row_errors));
        meta.insert("records_recovered".into(), json!(out.len()));
        meta.insert("detail".into(), json!(detail.clone()));
        meta.insert(
            "name".into(),
            json!(format!("Windows Timeline: incomplete — {detail}")),
        );
        out.push(
            Artifact::new(case, ArtifactType::ParsedRecord, None, Value::Object(meta))
                .with_parent(parent)
                .with_subtype("parse_incomplete"),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_activity_table(
    conn: &Connection,
    table: &'static str,
    cols: &std::collections::HashSet<String>,
    packages: &HashMap<String, Vec<AppIdEntry>>,
    case: Uuid,
    parent: Uuid,
    out: &mut Vec<Artifact>,
    walk: &mut WalkGaps,
) {
    let (proj, idx) = projection(cols, ACTIVITY_COLUMNS);
    if proj.is_empty() {
        walk.activity_query_failed = true;
        return;
    }
    let sql = format!("SELECT {proj} FROM [{table}]");
    let Ok(mut stmt) = conn.prepare(&sql) else {
        walk.activity_query_failed = true;
        return;
    };
    // Collect the raw cells into an owned row so decoding happens outside the
    // rusqlite closure (which cannot allocate our record types).
    let Ok(rows) = stmt.query_map([], |r| Ok(read_raw_row(r, &idx))) else {
        walk.activity_query_failed = true;
        return;
    };
    for row in rows {
        // Every dropped row is one activity missing from the history.
        let Ok(raw) = row else {
            walk.activity_row_errors += 1;
            continue;
        };
        if let Some(art) = build_record(raw, table, packages, case, parent) {
            out.extend(art);
        }
    }
}

/// The owned, still-undecoded cell set for one activity row.
struct RawRow {
    id: Option<String>,
    app_id_raw: Option<String>,
    activity_type: Option<i64>,
    activity_status: Option<i64>,
    group: Option<String>,
    payload: Option<String>,
    clipboard_payload: Option<String>,
    start: Option<i64>,
    end: Option<i64>,
    last_modified: Option<i64>,
    expiration: Option<i64>,
    last_modified_on_client: Option<i64>,
    created_in_cloud: Option<i64>,
    is_local_only: Option<i64>,
    platform_device_id: Option<String>,
    operation_type: Option<i64>,
    operation_order: Option<i64>,
}

fn read_raw_row(r: &Row, idx: &HashMap<&str, usize>) -> RawRow {
    RawRow {
        id: idx.get("Id").and_then(|&i| cid(r, i)),
        app_id_raw: get_blob(r, idx, "AppId"),
        activity_type: get_i(r, idx, "ActivityType"),
        activity_status: get_i(r, idx, "ActivityStatus"),
        group: get_s(r, idx, "Group"),
        payload: get_blob(r, idx, "Payload"),
        clipboard_payload: get_blob(r, idx, "ClipboardPayload"),
        start: get_i(r, idx, "StartTime"),
        end: get_i(r, idx, "EndTime"),
        last_modified: get_i(r, idx, "LastModifiedTime"),
        expiration: get_i(r, idx, "ExpirationTime"),
        last_modified_on_client: get_i(r, idx, "LastModifiedOnClient"),
        created_in_cloud: get_i(r, idx, "CreatedInCloud"),
        is_local_only: get_i(r, idx, "IsLocalOnly"),
        platform_device_id: get_s(r, idx, "PlatformDeviceId"),
        operation_type: get_i(r, idx, "OperationType"),
        operation_order: get_i(r, idx, "OperationOrder"),
    }
}

/// Turn one decoded row into a `ParsedRecord` (always) plus a `TimelineEvent`
/// (only when `StartTime` is a valid positive instant).
fn build_record(
    raw: RawRow,
    table: &'static str,
    packages: &HashMap<String, Vec<AppIdEntry>>,
    case: Uuid,
    parent: Uuid,
) -> Option<Vec<Artifact>> {
    let app_ids = raw
        .app_id_raw
        .as_deref()
        .map(parse_app_ids)
        .unwrap_or_default();
    let pkg_entries = raw
        .id
        .as_ref()
        .and_then(|id| packages.get(id))
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let executable = resolve_executable(&app_ids, pkg_entries);

    let payload = decode_payload(raw.payload.as_deref());
    let clipboard = decode_clipboard(raw.clipboard_payload.as_deref());

    let start = pos_time(raw.start);
    let end = pos_time(raw.end);
    let duration = match (start, end) {
        (Some(s), Some(e)) if e > s => e.checked_sub(s),
        _ => None,
    };

    let label = activity_type_label(raw.activity_type);

    // --- build the ParsedRecord metadata (discriminator `type` first) --------
    let mut m = Map::new();
    m.insert("type".into(), json!("WindowsTimelineActivity"));
    m.insert("subtype".into(), json!("windows_timeline_activity"));
    m.insert("platform".into(), json!("Windows"));
    m.insert("source_table".into(), json!(table));

    if let Some(id) = &raw.id {
        m.insert("activity_id".into(), json!(id));
    }
    if let Some(exe) = &executable {
        m.insert("executable".into(), json!(exe));
    }
    if let Some(app) = &payload.app_display_name {
        m.insert("app_display_name".into(), json!(app));
    }
    if let Some(raw_appid) = &raw.app_id_raw {
        let mut r = raw_appid.clone();
        let mut appid_truncated = false;
        if r.len() > APPID_RAW_CAP {
            // Cut on a char boundary: `String::truncate` PANICS mid-code-point,
            // and an AppId blob is arbitrary evidence text, so a multi-byte
            // character landing on the cap would abort the whole database's
            // parse and render as "this machine has no Timeline".
            let mut cut = APPID_RAW_CAP;
            while cut > 0 && !r.is_char_boundary(cut) {
                cut -= 1;
            }
            r.truncate(cut);
            appid_truncated = true;
        }
        m.insert("app_id_raw".into(), json!(r));
        // Always stated, so "short AppId" and "AppId we cut" differ.
        m.insert("app_id_raw_truncated".into(), json!(appid_truncated));
        if appid_truncated {
            m.insert("content_incomplete".into(), json!(true));
            m.insert(
                "content_incomplete_reason".into(),
                json!("app_id_raw_capped"),
            );
        }
    }

    if let Some(t) = raw.activity_type {
        m.insert("activity_type".into(), json!(t));
    }
    m.insert("activity_type_label".into(), json!(label));
    if let Some(s) = raw.activity_status {
        m.insert("activity_status".into(), json!(s));
    }
    if let Some(g) = &raw.group {
        m.insert("group".into(), json!(g));
    }

    if let Some(dt) = &payload.display_text {
        m.insert("display_text".into(), json!(dt));
    }
    if let Some(d) = &payload.description {
        m.insert("description".into(), json!(d));
    }
    if let Some(u) = &payload.content_uri {
        m.insert("content_uri".into(), json!(u));
    }
    if let Some(u) = &payload.activation_uri {
        m.insert("activation_uri".into(), json!(u));
    }
    if let Some(r) = &payload.reporting_app {
        m.insert("reporting_app".into(), json!(r));
    }
    m.insert("payload_binary".into(), json!(payload.payload_binary));

    if let Some(clip) = &clipboard {
        if is_clipboard_type(raw.activity_type) || clip.text.is_some() {
            m.insert("has_clipboard".into(), json!(clip.text.is_some()));
            if let Some(t) = &clip.text {
                m.insert("clipboard_text".into(), json!(t));
                // Always stated, so "short clip" and "clip we cut" differ.
                m.insert(
                    "clipboard_text_truncated".into(),
                    json!(clip.text_truncated),
                );
                m.insert("clipboard_bytes".into(), json!(clip.bytes_len));
                if clip.text_truncated {
                    m.insert("content_incomplete".into(), json!(true));
                    m.insert(
                        "content_incomplete_reason".into(),
                        json!("clipboard_text_capped"),
                    );
                }
            } else {
                m.insert("clipboard_bytes".into(), json!(clip.bytes_len));
            }
            if let Some(f) = &clip.format {
                m.insert("clipboard_format".into(), json!(f));
            }
        }
    }

    // --- timestamps: raw unix seconds (>0) + ISO display; omitted when unset --
    if let Some(s) = start {
        m.insert("date".into(), json!(s));
        m.insert("start_time".into(), json!(s));
        if let Some(iso) = iso8601(s) {
            m.insert("start_time_iso".into(), json!(iso));
        }
    }
    if let Some(e) = end {
        m.insert("end_time".into(), json!(e));
        if let Some(iso) = iso8601(e) {
            m.insert("end_time_iso".into(), json!(iso));
        }
    }
    if let Some(d) = duration {
        m.insert("duration_seconds".into(), json!(d));
    }
    if let Some(ad) = payload.active_duration_seconds {
        m.insert("active_duration_seconds".into(), json!(ad));
    }
    if let Some(lm) = pos_time(raw.last_modified) {
        m.insert("last_modified_time".into(), json!(lm));
    }
    if let Some(lmc) = pos_time(raw.last_modified_on_client) {
        m.insert("last_modified_on_client".into(), json!(lmc));
    }
    // `CreatedInCloud` 0 is meaningful ("local"); surface the raw value when the
    // column exists.
    if let Some(cic) = raw.created_in_cloud {
        m.insert("created_in_cloud".into(), json!(cic));
    }
    if let Some(exp) = pos_time(raw.expiration) {
        m.insert("expiration_time".into(), json!(exp));
    }
    if let Some(lo) = raw.is_local_only {
        m.insert("is_local_only".into(), json!(lo));
    }
    if let Some(dev) = &raw.platform_device_id {
        m.insert("platform_device_id".into(), json!(dev));
    }
    if let Some(dp) = &payload.device_platform {
        m.insert("device_platform".into(), json!(dp));
    }
    if let Some(tz) = &payload.user_timezone {
        m.insert("user_timezone".into(), json!(tz));
    }

    // Activity_PackageId cross-reference.
    if !pkg_entries.is_empty() {
        let pkgs: Vec<Value> = pkg_entries
            .iter()
            .map(|e| json!({ "platform": e.platform, "name": e.application }))
            .collect();
        m.insert("packages".into(), json!(pkgs));
    }

    // ActivityOperation extras.
    if let Some(ot) = raw.operation_type {
        m.insert("operation_type".into(), json!(ot));
    }
    if let Some(oo) = raw.operation_order {
        m.insert("operation_order".into(), json!(oo));
    }

    let app_label = payload
        .app_display_name
        .clone()
        .or_else(|| executable.as_deref().map(exe_basename));
    let name = payload
        .display_text
        .clone()
        .or_else(|| executable.clone())
        .or_else(|| payload.app_display_name.clone())
        .unwrap_or_else(|| "Windows Timeline Activity".into());
    let short_desc = build_short_desc(
        app_label.as_deref(),
        payload.display_text.as_deref(),
        &label,
        payload.active_duration_seconds,
    );
    m.insert("name".into(), json!(name));
    m.insert("short_desc".into(), json!(short_desc));

    let record =
        Artifact::new(case, ArtifactType::ParsedRecord, None, Value::Object(m)).with_parent(parent);

    let mut arts = vec![record];

    // --- TimelineEvent (only with a valid StartTime) -------------------------
    if let Some(s) = start {
        let mut fd = Map::new();
        if let Some(id) = &raw.id {
            fd.insert("activity_id".into(), json!(id));
        }
        if let Some(exe) = &executable {
            fd.insert("executable".into(), json!(exe));
        }
        if let Some(t) = raw.activity_type {
            fd.insert("activity_type".into(), json!(t));
        }
        fd.insert("activity_type_label".into(), json!(label));
        if let Some(dt) = &payload.display_text {
            fd.insert("display_text".into(), json!(dt));
        }
        if let Some(u) = &payload.content_uri {
            fd.insert("content_uri".into(), json!(u));
        }
        if let Some(d) = duration {
            fd.insert("duration_seconds".into(), json!(d));
        }
        if let Some(ad) = payload.active_duration_seconds {
            fd.insert("active_duration_seconds".into(), json!(ad));
        }
        if let Some(e) = end {
            fd.insert("end_time".into(), json!(e));
        }
        if let Some(lm) = pos_time(raw.last_modified) {
            fd.insert("last_modified_time".into(), json!(lm));
        }
        if let Some(clip) = clipboard.as_ref().and_then(|c| c.text.as_ref()) {
            fd.insert("clipboard_text".into(), json!(clip));
        }
        fd.insert("source_table".into(), json!(table));
        if let Some(dev) = &raw.platform_device_id {
            fd.insert("platform_device_id".into(), json!(dev));
        }

        let filename = payload
            .content_uri
            .clone()
            .or_else(|| payload.display_text.clone());

        let mut ev = Map::new();
        ev.insert("timestamp".into(), json!(s));
        ev.insert("timestamp_desc".into(), json!("Windows Timeline Activity"));
        ev.insert("source_module".into(), json!(MODULE_ID));
        ev.insert("short_desc".into(), json!(short_desc));
        if let Some(f) = filename {
            ev.insert("filename".into(), json!(f));
        }
        if let Some(tz) = &payload.user_timezone {
            ev.insert("user_timezone".into(), json!(tz));
        }
        ev.insert("full_details".into(), json!(Value::Object(fd).to_string()));

        arts.push(
            Artifact::new(case, ArtifactType::TimelineEvent, None, Value::Object(ev))
                .with_parent(parent),
        );
    }

    Some(arts)
}

fn exe_basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn build_short_desc(
    app_label: Option<&str>,
    display_text: Option<&str>,
    type_label: &str,
    active_duration: Option<i64>,
) -> String {
    let mut base = match (app_label, display_text) {
        (Some(a), Some(d)) => format!("{a} — {d}"),
        (Some(a), None) => a.to_string(),
        (None, Some(d)) => d.to_string(),
        (None, None) => type_label.to_string(),
    };
    if let Some(ad) = active_duration.filter(|&d| d > 0) {
        base.push_str(&format!(" (focus {ad}s)"));
    }
    base
}

#[cfg(test)]
mod tests;
