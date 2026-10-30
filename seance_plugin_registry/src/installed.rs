//! Installed programs, read from a hive's `Uninstall` keys.
//!
//! Windows records every program that registered an uninstaller as one subkey
//! of `Microsoft\Windows\CurrentVersion\Uninstall`: machine-wide installs in
//! SOFTWARE (64-bit ones under the native path, 32-bit ones on a 64-bit OS
//! under `Wow6432Node`), per-user installs in each NTUSER.DAT. The NIST CFReDS
//! Data Leakage key asks "what applications were installed by the suspect
//! after installing the OS", and this is the record that answers it.
//!
//! One `InstalledProgram` record per subkey, no exceptions. Many entries are a
//! product GUID with an `UninstallString` and nothing else; a builder that
//! kept only the named ones would make "the hive holds 40 entries" and "the
//! product lists 31 programs" both true, and an examiner counting installs
//! would be wrong by the difference. Nothing is emitted for a hive with no
//! `Uninstall` key: the absence of records is the statement, and the hive
//! record's own key count already proves the hive was walked.
//!
//! Everything here reads the key and value lists the hive walk already
//! produced, so it is testable without hive bytes.

use seance_core::artifact::{Artifact, ArtifactType};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

#[cfg(test)]
#[path = "installed_tests.rs"]
mod tests;

/// The `timestamp_desc` the raw NK scan puts on its key-write events; the
/// only events on the output list that carry a per-key last-write time.
const KEY_WRITE_DESC: &str = "Registry Key Last Written";

/// An incomplete stamp already on the hive record, passed on to every
/// program read out of it. The list of programs is a subset of what the hive
/// held whenever the hive itself was, and each entry outlives the hive record
/// in a list or an export.
pub(crate) struct Incomplete {
    pub reason: String,
    pub detail: Option<String>,
}

/// What every program record inherits from the hive it was read out of.
pub(crate) struct HiveContext<'a> {
    pub case_id: uuid::Uuid,
    /// The file artifact the hive was parsed from — the same parent the hive
    /// record and its USB devices hang off.
    pub parent_id: uuid::Uuid,
    pub hive_type: &'a str,
    pub source_path: Option<&'a str>,
    /// `live`, `regback` or `unknown`, as the hive record judged from its
    /// path. A volume holds the same SOFTWARE hive several times over — live,
    /// RegBack, every shadow copy — and each copy's programs are emitted, so
    /// a consumer counting programs must be able to tell which copy a record
    /// came from without parsing the path.
    pub hive_role: &'a str,
    /// The hive's compact replay stamp (`HiveRecovery::child_stamp`).
    pub replay: &'a Value,
    pub incomplete: Option<Incomplete>,
    /// Why the raw NK scan stopped short of the whole hive (the hive record's
    /// `key_timeline_cap_reason`), or `None` when it ran to completion. A key
    /// the scan never reached has no last-write time to give, and the record
    /// must say the scan was the reason rather than the key.
    pub key_scan_incomplete: Option<&'a str>,
}

/// Where an `Uninstall` entry sits, read off its key path.
struct Placement {
    /// `machine` for SOFTWARE, `user` for a `Software\...` path in a user hive.
    scope: &'static str,
    /// The entry is under `Wow6432Node`: a 32-bit program on a 64-bit OS.
    wow64: bool,
}

/// Classify a key path as an `Uninstall` entry, or `None` for any other key.
///
/// Exactly one segment below the `Uninstall` key counts. The key itself is
/// not a program, and `...\Uninstall\Foo\Private` is Foo's own state — an
/// installer's nested keys would otherwise inflate the list.
///
/// The scope is read from the path, not the hive's file name: a hive named
/// `Unknown` (the walk's default) or one lifted under a copied name still
/// spells `Software\Microsoft\...` when it is a user hive and
/// `Microsoft\...` straight off the root when it is SOFTWARE.
fn classify(key_path: &str) -> Option<Placement> {
    const MARKER: [&str; 4] = ["microsoft", "windows", "currentversion", "uninstall"];
    let segments: Vec<&str> = key_path.split('\\').collect();
    // The root plus the four marker segments plus the entry itself.
    if segments.len() < MARKER.len() + 2 {
        return None;
    }
    let entry_at = segments.len() - 1;
    let marker_at = entry_at - MARKER.len();
    let marker_matches = segments[marker_at..entry_at]
        .iter()
        .zip(MARKER.iter())
        .all(|(seg, want)| seg.eq_ignore_ascii_case(want));
    if !marker_matches || segments[entry_at].is_empty() {
        return None;
    }
    // What is left above the marker: the hive root, optionally `Software`
    // (a user hive), optionally `Wow6432Node`.
    let mut above = &segments[..marker_at];
    let wow64 = above
        .last()
        .is_some_and(|s| s.eq_ignore_ascii_case("Wow6432Node"));
    if wow64 {
        above = &above[..above.len() - 1];
    }
    match above {
        [_root] => Some(Placement {
            scope: "machine",
            wow64,
        }),
        [_root, software] if software.eq_ignore_ascii_case("Software") => Some(Placement {
            scope: "user",
            wow64,
        }),
        // A deeper path that happens to end in the marker (a mounted hive
        // mirrored under another key, a backup someone imported) is not a
        // place Windows reads installs from, and is not claimed as one.
        _ => None,
    }
}

/// The path with its root segment removed and case folded, for matching the
/// hive walk's paths against the raw NK scan's.
///
/// The walk names the root as the hive reader reports it; the scan rebuilds paths
/// from NK parent chains and names the root as the NK cell spells it, or
/// `(root)` when the cell's name is empty. Below the root the two agree, and
/// a hive has one root, so the root segment carries no information.
fn rootless_key(key_path: &str) -> String {
    key_path
        .split_once('\\')
        .map(|(_, rest)| rest)
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Index the key-write events the raw NK scan already emitted by key path,
/// so a program record can carry its own key's last-write time.
///
/// The NK timestamp is not exposed by the walk; the scan over the raw cells is
/// the only source of it, and it has already run by the time the program
/// records are built. Reading the times back off its events costs one pass
/// over the output list rather than a second pass over the hive bytes.
pub(crate) fn key_write_times(events: &[Artifact]) -> HashMap<String, String> {
    events
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::TimelineEvent)
        .filter(|a| a.metadata["timestamp_desc"] == KEY_WRITE_DESC)
        .filter_map(|a| {
            let path = a.metadata["key_path"].as_str()?;
            let ts = a.metadata["timestamp"].as_str()?;
            Some((rootless_key(path), ts.to_string()))
        })
        .collect()
}

/// Decode an `InstallDate` of the documented `YYYYMMDD` shape to
/// `YYYY-MM-DD`. `None` for any other shape, including eight digits that are
/// not a calendar date — "2015-13-00" is not a date this build will put in a
/// report.
fn decode_install_date(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year: i32 = s[0..4].parse().ok()?;
    let month: u32 = s[4..6].parse().ok()?;
    let day: u32 = s[6..8].parse().ok()?;
    let date = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    Some(date.format("%Y-%m-%d").to_string())
}

/// Read the integer out of the hive walk's REG_DWORD / REG_QWORD rendering,
/// `0x%08x (n)`. Anything else — a REG_SZ that spells a number, a binary
/// blob — is not that shape and yields `None`: the integer is read, never
/// guessed from a string an installer chose to write.
fn parse_rendered_integer(rendered: &str) -> Option<u64> {
    let s = rendered.trim();
    if !s.starts_with("0x") {
        return None;
    }
    let inner = s.strip_suffix(')')?.rsplit_once(" (")?.1;
    inner.parse::<u64>().ok()
}

/// A REG_SZ as the walk rendered it, or `None` when there is no text to
/// carry. The walk spells a zero-length value `(empty string)`; that and a
/// bare terminator both mean the installer wrote nothing.
fn text(rendered: Option<&str>) -> Option<&str> {
    // The walk renders a value it could not read as "(error reading value:
    // …)" / "(error converting data: …)" in the value's own slot. That is the
    // walk's note about the value, not the value, and a publisher or version
    // field must not carry it as if the hive said so.
    rendered
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "(empty string)" && !s.starts_with("(error "))
}

/// Build one `InstalledProgram` record per `Uninstall` subkey, plus one
/// `TimelineEvent` per record that carries a decodable `InstallDate`.
///
/// Entries are gathered from the key list and the value list both: a subkey
/// with no values at all appears only in the former, and a caller that has
/// only values (a test, a consumer of an older hive record) still gets every
/// entry the values name. Output is ordered by key path so two runs over the
/// same hive list the same programs in the same order.
pub(crate) fn build_installed_program_records(
    all_keys: &[Value],
    all_values: &[Value],
    key_times: &HashMap<String, String>,
    ctx: &HiveContext<'_>,
) -> Vec<Artifact> {
    // Every Uninstall entry, with its values keyed by lower-cased name.
    let mut entries: BTreeMap<String, HashMap<String, String>> = BTreeMap::new();
    for k in all_keys {
        let Some(path) = k.get("key_path").and_then(Value::as_str) else {
            continue;
        };
        if classify(path).is_some() {
            entries.entry(path.to_string()).or_default();
        }
    }
    for v in all_values {
        let (Some(path), Some(name), Some(data)) = (
            v.get("key_path").and_then(Value::as_str),
            v.get("value_name").and_then(Value::as_str),
            v.get("value_data").and_then(Value::as_str),
        ) else {
            continue;
        };
        if classify(path).is_none() {
            continue;
        }
        entries
            .entry(path.to_string())
            .or_default()
            .insert(name.to_ascii_lowercase(), data.to_string());
    }

    let mut out = Vec::with_capacity(entries.len() * 2);
    for (key_path, values) in &entries {
        let Some(place) = classify(key_path) else {
            continue;
        };
        let key_name = key_path.rsplit('\\').next().unwrap_or(key_path);
        let get = |name: &str| text(values.get(name).map(String::as_str));

        let display_name = get("displayname");
        let display_version = get("displayversion");
        let publisher = get("publisher");

        // InstallDate: present and decoded, present and not, or absent — three
        // states an examiner must be able to tell apart. The raw text stays on
        // the record whenever there was any, so a date this build would not
        // decode is still there to be read by eye.
        let install_date_raw = get("installdate");
        let install_date = install_date_raw.and_then(decode_install_date);
        let install_date_source = match (install_date_raw, &install_date) {
            (None, _) => "absent",
            (Some(_), Some(_)) => "InstallDate value",
            (Some(_), None) => "InstallDate value (not YYYYMMDD)",
        };

        let estimated_size_kb = get("estimatedsize").and_then(parse_rendered_integer);
        // SystemComponent = 1 is how Windows hides an entry from Programs and
        // Features; absent or any other value shows it.
        let system_component = get("systemcomponent")
            .and_then(parse_rendered_integer)
            .is_some_and(|v| v == 1);

        let (key_last_written, key_last_written_source) = match (
            key_times.get(&rootless_key(key_path)),
            ctx.key_scan_incomplete,
        ) {
            (Some(ts), _) => (json!(ts), "NK last-write time (raw cell scan)".to_string()),
            (None, Some(why)) => (
                Value::Null,
                format!("absent (key-write scan incomplete: {why})"),
            ),
            (None, None) => (Value::Null, "absent".to_string()),
        };

        let shown_name = display_name.unwrap_or(key_name);
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("InstalledProgram"));
        m.insert("subtype".into(), json!("installed_program"));
        m.insert(
            "name".into(),
            json!(format!("Installed program: {shown_name}")),
        );
        m.insert("key_name".into(), json!(key_name));
        m.insert("display_name".into(), json!(display_name));
        m.insert("display_version".into(), json!(display_version));
        m.insert("publisher".into(), json!(publisher));
        m.insert("install_location".into(), json!(get("installlocation")));
        m.insert("install_source".into(), json!(get("installsource")));
        m.insert("uninstall_string".into(), json!(get("uninstallstring")));
        m.insert("install_date".into(), json!(install_date));
        m.insert("install_date_source".into(), json!(install_date_source));
        m.insert("install_date_raw".into(), json!(install_date_raw));
        m.insert("estimated_size_kb".into(), json!(estimated_size_kb));
        m.insert("system_component".into(), json!(system_component));
        m.insert("wow64".into(), json!(place.wow64));
        m.insert("scope".into(), json!(place.scope));
        m.insert("hive_type".into(), json!(ctx.hive_type));
        m.insert("hive".into(), json!(ctx.hive_type));
        m.insert("source_path".into(), json!(ctx.source_path));
        m.insert("hive_role".into(), json!(ctx.hive_role));
        m.insert("key_path".into(), json!(key_path));
        m.insert("key_last_written".into(), key_last_written);
        m.insert(
            "key_last_written_source".into(),
            json!(key_last_written_source),
        );
        // The hive this came from: recovered, stale, or clean.
        m.insert("replay".into(), ctx.replay.clone());
        if let Some(inc) = &ctx.incomplete {
            m.insert("content_incomplete".into(), json!(true));
            m.insert("content_incomplete_reason".into(), json!(inc.reason));
            if let Some(detail) = &inc.detail {
                m.insert("content_incomplete_detail".into(), json!(detail));
            }
        }

        let record = Artifact::new(
            ctx.case_id,
            ArtifactType::ParsedRecord,
            None,
            Value::Object(m),
        )
        .with_parent(ctx.parent_id)
        .with_subtype("installed_program");

        // The install date is the only dated fact an entry carries, so it is
        // the only event. It is a calendar day with no time and no zone:
        // midnight UTC is the timeline's placement of the day, and the event
        // says so rather than letting the 00:00:00 read as a clock reading.
        let event = install_date.as_deref().map(|date| {
            let short_desc = match display_version {
                Some(v) => format!("Program installed: {shown_name} {v}"),
                None => format!("Program installed: {shown_name}"),
            };
            Artifact::new(
                ctx.case_id,
                ArtifactType::TimelineEvent,
                None,
                json!({
                    "timestamp": format!("{date}T00:00:00Z"),
                    "timestamp_desc": "Program installed (InstallDate)",
                    "timestamp_precision": "day",
                    "source_module": "plugin.windows.registry_parser",
                    "short_desc": short_desc,
                    "full_details": json!({
                        "display_name": display_name,
                        "display_version": display_version,
                        "publisher": publisher,
                        "key_path": key_path,
                        "install_date": date,
                        "install_date_raw": install_date_raw,
                        "time_of_day": "not recorded — InstallDate is a calendar day with no time or zone; placed at 00:00:00 UTC",
                        "scope": place.scope,
                        "wow64": place.wow64,
                        "hive_type": ctx.hive_type,
                        "source_path": ctx.source_path,
                        "replay": ctx.replay,
                    })
                    .to_string(),
                }),
            )
            .with_parent(record.id)
        });

        out.push(record);
        out.extend(event);
    }
    out
}

/// The hive parser's one entry point: derive the program records from the
/// walk's key and value lists and append them to `out`.
///
/// The hive record supplies the hive's type, its path and any incomplete
/// stamp it already carries; the key-write events already on `out` supply
/// per-key last-write times. `replay` is the hive's compact recovery stamp.
pub(crate) fn emit_installed_programs(
    out: &mut Vec<Artifact>,
    all_keys: &[Value],
    all_values: &[Value],
    hive: &Artifact,
    replay: &Value,
) {
    let meta = &hive.metadata;
    let incomplete = if meta["content_incomplete"] == true {
        Some(Incomplete {
            reason: meta["content_incomplete_reason"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            detail: meta["content_incomplete_detail"]
                .as_str()
                .map(str::to_string),
        })
    } else {
        None
    };
    let ctx = HiveContext {
        case_id: hive.case_id,
        parent_id: hive.parent_id.unwrap_or(hive.id),
        hive_type: meta["hive_type"].as_str().unwrap_or("Unknown"),
        source_path: meta["source_path"].as_str(),
        hive_role: meta["hive_role"].as_str().unwrap_or("unknown"),
        replay,
        incomplete,
        // The scan's own account of itself, as stamped on the hive record. A
        // record that says the scan completed carries no cap reason.
        key_scan_incomplete: match meta["key_timeline_complete"].as_bool() {
            Some(false) => Some(
                meta["key_timeline_cap_reason"]
                    .as_str()
                    .unwrap_or("unknown"),
            ),
            _ => None,
        },
    };
    let times = key_write_times(out);
    out.extend(build_installed_program_records(
        all_keys, all_values, &times, &ctx,
    ));
}
