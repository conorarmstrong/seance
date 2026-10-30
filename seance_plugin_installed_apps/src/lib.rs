#![forbid(unsafe_code)]
//! Installed-application inventory parser (Android + iOS).
//!
//! [`InstalledAppsParser`] inspects file artifacts and self-selects the Android
//! package-manager inventories and the iOS application-state database, emitting
//! one `InstalledApp` [`ParsedRecord`](ArtifactType::ParsedRecord) per installed
//! application plus one `InstalledAppSummary` record per parsed file.
//!
//! # Supported inputs
//!
//! - `/data/system/packages.xml` — the package-manager settings XML. Each
//!   `<package>` element carries the package id (`name`), `codePath`, install
//!   times (`ft`/`it`/`ut`, each a **hex** string of Unix epoch milliseconds),
//!   `version` and `userId`/`sharedUserId`. Non-`<package>` elements
//!   (`<shared-user>`, `<permissions>`, `<keyset-settings>`, ...) are ignored.
//!   Android 12 and later write this file as Android Binary XML (`ABX\0`
//!   magic) rather than text; it is detected by magic and decoded to text
//!   through [`seance_xml_util::abx`] before the same walk. The summary says
//!   which encoding was read (`encoding: "abx" | "text"`) — a text parser
//!   handed the binary form reports zero packages, and on every modern device
//!   that is where the install times are (HUNT-069).
//! - `/data/system/packages.list` — plain text, one app per line, space
//!   separated: `packageName userId debugFlag dataPath seinfo gids [...]`.
//! - iOS `applicationState.db` — a SQLite database whose
//!   `application_identifier_tab` table lists every installed app's bundle id.
//!
//! # Timestamps
//!
//! The hex `ft`/`it`/`ut` values decode to Unix epoch milliseconds and are surfaced
//! both as an integer (`first_install` / `install_time` / `update_time`) and an
//! RFC 3339 string (`*_rfc3339`). Absurd values (non-hex, non-positive, or beyond
//! the year 2100) are dropped rather than fabricated.
//!
//! # Honesty & robustness
//!
//! Absent fields are omitted, never emitted as null. Corrupt, truncated, or
//! non-UTF-8 input never panics and never fails the pipeline: whatever fully parsed
//! is emitted, otherwise an empty result.
//!
//! # Schema-drift defence (`applicationState.db`)
//!
//! FrontBoard keeps its schema version as the single row of `schema(version)`;
//! its `PRAGMA user_version` is 0 (SQLite's unset default) and is not consulted.
//! Both real stores this project holds (ios2022ffs, macos2021) carry 1, so the
//! validated range is `1..=1`. The `application_identifier` column is resolved
//! through a candidate list before the query is written. A store outside the
//! range, one with no `schema` table, or one whose identifier column no candidate
//! matched is still inventoried as far as it can be, and a `ParserStaleWarning`
//! record is appended naming the version seen or the field unresolved. See
//! [`schema_support`].

pub mod macos;
#[cfg(test)]
mod schema_golden_tests;
mod schema_support;
pub use macos::MacInstalledAppsParser;
use schema_support::{
    assess_version, plan_columns, single_row_version, unresolved_fields_marker, SchemaSupport,
};

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_capped, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{looks_like_sqlite, open_readonly, SupportedRange, TempDb};
use seance_xml_util::abx::{self, AbxError};
use seance_xml_util::XmlGuard;
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use tracing::debug;
use uuid::Uuid;

/// Cap on how many bytes of an inventory file to read (64 MiB). These files are
/// kilobytes to low megabytes in practice; the cap bounds a pathological input.
const MAX_CONTENT_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound for a plausible install epoch: `2100-01-01T00:00:00Z` in ms.
/// Decoded hex timestamps beyond this are treated as garbage and dropped.
const MAX_PLAUSIBLE_EPOCH_MS: i64 = 4_102_444_800_000;

/// The schema this parser was validated against for `applicationState.db`:
/// FrontBoard keeps its version as the single row of `schema(version)`, and
/// both real stores this project holds carry 1. `PRAGMA user_version` is 0 on
/// both — SQLite's unset default — and is not consulted.
const IOS_APPSTATE_SUPPORT: SchemaSupport = SchemaSupport {
    app: "ios-applicationstate",
    store: "applicationState.db",
    record_type: "InstalledApp",
    range: SupportedRange {
        min: 1,
        max: Some(1),
    },
    evidence: "ios2022ffs /private/var/mobile/Library/FrontBoard/applicationState.db and \
               macos2021 Users/eliflatt/Library/FrontBoard/applicationState.db (schema.version 1)",
};

/// The one column the inventory is: a rename would otherwise read as "no apps
/// were installed".
const IOS_APPSTATE_FIELDS: &[(&str, &[&str])] =
    &[("application_identifier", &["application_identifier"])];

/// Which inventory format the source artifact is.
#[derive(Clone, Copy)]
enum Source {
    Xml,
    List,
    /// iOS `applicationState.db` (SQLite), inventory of installed bundle ids.
    IosAppState,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Xml => "packages.xml",
            Source::List => "packages.list",
            Source::IosAppState => "applicationState.db",
        }
    }
}

/// Parses Android installed-application inventories into `InstalledApp` records.
pub struct InstalledAppsParser;

impl InstalledAppsParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for InstalledAppsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for InstalledAppsParser {
    fn id(&self) -> &str {
        "plugin.mobile.installed_apps"
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
        let Some(source) = detect_source(name, path) else {
            return Ok(Vec::new());
        };

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

        debug!(
            "InstalledAppsParser parsing {} as {}",
            name,
            source.as_str()
        );

        let declared = data.size();
        let content = read_capped(data.as_ref(), MAX_CONTENT_BYTES);
        // The inventory file was not read to its declared end (over the cap, or a
        // truncated/broken source). Whatever parsed is a prefix, so the app list
        // and its count are a floor, not the installed set (B2-087).
        let bytes_short = (content.len() as u64) < declared;

        let mut encoding = None;
        let mut abx_lossy_strings = 0usize;
        let mut parse_reason = None;
        let mut parse_offset = None;
        let mut stale = Vec::new();
        let (mut apps, parse_incomplete, parse_detail) = match source {
            Source::Xml => {
                let read = parse_packages_xml(&content, artifact.case_id, artifact.id);
                let PackagesXmlRead {
                    apps,
                    stopped_early: stopped,
                    guard,
                    encoding: read_encoding,
                    abx_error,
                    abx_lossy_strings: lossy,
                } = read;
                encoding = Some(read_encoding);
                abx_lossy_strings = lossy;
                let attr_errors = guard.attribute_errors() as u64;
                let detail = if let Some(err) = abx_error.as_ref() {
                    // The binary document ended, or broke, before END_DOCUMENT.
                    // Every package decoded before that point is real; every
                    // package after it was never seen. A document that simply
                    // ends is a short read; bytes that do not form a document
                    // are an unresolved structure, so an examiner is not sent
                    // looking for the rest of a file that has no rest.
                    parse_reason = Some(match err {
                        AbxError::Truncated { .. } => IncompleteReason::ShortRead,
                        AbxError::DecodedTooLarge { .. } => IncompleteReason::CapReached,
                        _ => IncompleteReason::UnresolvedStructure,
                    });
                    parse_offset = err.offset().map(|o| o as u64);
                    Some(format!(
                        "the ABX packages.xml could not be decoded to its end: {err}; \
                         packages after that point were never seen"
                    ))
                } else if stopped {
                    Some("the packages.xml walk stopped on a parse error".to_string())
                } else if guard.attributes_truncated() {
                    // Distinct from a decode failure: these attributes were
                    // readable and were refused, because the element carried
                    // more than any legitimate `<package>` does. Named
                    // separately so an examiner is not told the device was
                    // damaged when what it was, was crafted.
                    Some(format!(
                        "{} package element(s) carried more attributes than the parser \
                         admits; the remainder were not read, so an application's \
                         details may be incomplete",
                        guard.elements_with_truncated_attributes()
                    ))
                } else if attr_errors > 0 {
                    Some(format!(
                        "{attr_errors} package attributes could not be decoded; an \
                         application whose name attribute was among them is missing from \
                         this inventory"
                    ))
                } else {
                    None
                };
                (
                    apps,
                    abx_error.is_some()
                        || stopped
                        || attr_errors > 0
                        || guard.attributes_truncated(),
                    detail,
                )
            }
            Source::List => (
                parse_packages_list(&content, artifact.case_id, artifact.id),
                false,
                None,
            ),
            Source::IosAppState => {
                let read =
                    parse_ios_app_state(&content, data.as_ref(), artifact.case_id, artifact.id);
                stale = read.stale;
                (read.apps, read.detail.is_some(), read.detail)
            }
        };

        // Counted before the schema markers join the list: they qualify the
        // inventory and are not applications.
        let count = apps.len();
        apps.extend(stale);
        apps.push(summary_record(
            artifact.case_id,
            artifact.id,
            count,
            source.as_str(),
            InventoryRead {
                bytes_short,
                parse_incomplete,
                bytes_read: content.len() as u64,
                declared_size: declared,
                parse_detail,
                parse_reason,
                parse_offset,
                encoding,
                abx_lossy_strings,
            },
        ));

        Ok(apps)
    }
}

/// Decide whether this artifact is a supported installed-app inventory.
fn detect_source(name: &str, path: &str) -> Option<Source> {
    if name.eq_ignore_ascii_case("packages.xml") || path.ends_with("/system/packages.xml") {
        return Some(Source::Xml);
    }
    if name.eq_ignore_ascii_case("packages.list") || path.ends_with("/system/packages.list") {
        return Some(Source::List);
    }
    if name.eq_ignore_ascii_case("applicationState.db") {
        return Some(Source::IosAppState);
    }
    None
}

/// What walking one `packages.xml` produced.
struct PackagesXmlRead {
    apps: Vec<Artifact>,
    /// The text XML walk stopped on a parse error before the end of the
    /// document.
    stopped_early: bool,
    guard: XmlGuard,
    /// How the file was stored: `"abx"` or `"text"`.
    encoding: &'static str,
    /// Why the ABX decode stopped before `END_DOCUMENT`, when it did. The
    /// events decoded before the stop were still walked.
    abx_error: Option<AbxError>,
    /// ABX strings decoded with replacement characters.
    abx_lossy_strings: usize,
}

/// Parse `packages.xml`, emitting one record per `<package>` element.
///
/// The file is Android Binary XML on Android 12 and later and text before
/// that; both arrive here. ABX is decoded to text first and walked by the same
/// code, so the `ft`/`it`/`ut` values — `LONG_HEX` tokens in ABX, bare hex
/// strings in text — reach [`decode_hex_timestamp`] in one form.
///
/// A malformed or truncated document ends the walk mid-file: the packages
/// after the break are never seen, so the caller must not present the result
/// as the installed set. `stopped_early` and `abx_error` say which walk broke.
fn parse_packages_xml(content: &[u8], case_id: Uuid, parent_id: Uuid) -> PackagesXmlRead {
    let (text, encoding, abx_error, abx_lossy_strings) = if abx::is_abx(content) {
        let decoded = abx::decode(content);
        (
            Cow::Owned(abx::render_text_xml(&decoded.document)),
            "abx",
            decoded.error,
            decoded.document.lossy_strings,
        )
    } else {
        (String::from_utf8_lossy(content), "text", None, 0)
    };
    let mut reader = Reader::from_str(&text);
    let mut buf = Vec::new();
    let mut apps = Vec::new();
    let mut stopped_early = false;
    // `packages.xml` comes off the device under examination. The guard bounds
    // what one crafted `<package>` element can cost, and counts the attributes
    // the reader refused -- each one can be the `name` that identifies the
    // package, so the element is dropped entirely and an installed application
    // goes missing from the inventory.
    let mut guard = XmlGuard::default();

    loop {
        match reader.read_event_into(&mut buf) {
            // <package .../> may be an empty or a start element depending on
            // whether it has children; handle both.
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if e.name().as_ref() == b"package" {
                    if let Some(meta) = xml_package_metadata(&e, &mut guard) {
                        apps.push(
                            Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta)
                                .with_parent(parent_id),
                        );
                    }
                }
            }
            Ok(Event::Eof) => break,
            // Malformed / truncated XML: stop, keep whatever fully parsed, and
            // tell the caller the walk did not reach the end of the document.
            Err(_) => {
                stopped_early = true;
                break;
            }
            _ => {}
        }
        buf.clear();
    }

    PackagesXmlRead {
        apps,
        stopped_early,
        guard,
        encoding,
        abx_error,
        abx_lossy_strings,
    }
}

/// Which partition a package's code sits on.
///
/// Not a statement about who installed it. `/data/app` holds the code of an
/// app the user installed **and** of a system app the Play Store has since
/// updated — on the graded Android image, 62 of the 63 packages there carry
/// `installer="com.android.vending"` and most of those are Google's own. What
/// the partition does say is whether the code is on a read-only OS partition
/// or in user data, and that is what makes a missing installer mean something.
fn code_partition(code_path: &str) -> &'static str {
    let path = code_path.trim_start_matches('/');
    match path.split('/').next().unwrap_or_default() {
        "data" => "data",
        "system" | "system_ext" => "system",
        "product" => "product",
        "vendor" => "vendor",
        "apex" => "apex",
        _ => "other",
    }
}

/// Whether a partition is one the operating system ships read-only.
fn read_only_partition(partition: &str) -> bool {
    matches!(partition, "system" | "product" | "vendor" | "apex")
}

/// What an absent installer means when the code is in user data.
const NO_INSTALLER_NOTE: &str = concat!(
    "This package's code is in the user data partition and the package manager recorded NO ",
    "installer for it. On a device where every other data-partition package names one, that is ",
    "the signal a sideload leaves \u{2014} `adb install`, a file manager, or an installer that ",
    "did not register itself. It is a SIGNAL AND NOT A PROOF: the attribute can also be absent ",
    "because the record predates the device's Android version writing it, because the app was ",
    "restored from a backup, or because the installing package has since been uninstalled. ",
    "Compare it against the other data-partition packages on the same device before relying ",
    "on it."
);

/// And what it means when the code is on a read-only OS partition.
const SHIPPED_NOTE: &str = concat!(
    "This package's code is on a read-only OS partition, so the package manager recorded no ",
    "installer because nothing installed it \u{2014} it shipped with the operating system. The ",
    "absence of an installer here is NOT a sideload signal."
);

/// The `isOrphaned` flag is reported and not interpreted.
const ORPHANED_NOTE: &str = concat!(
    "The package manager's own `isOrphaned` flag, reported as written. What it selects is NOT ",
    "established here: on the two graded Android images \u{2014} 40 of the 62 packages installed ",
    "by the Play Store on an Android 9 Pixel 3, and 59 of the 123 on an Android 14 Pixel 7a ",
    "\u{2014} carry it while the Play Store itself is installed, so the common reading \u{2014} ",
    "that the installing package has since been uninstalled \u{2014} does not hold on either ",
    "device."
);

/// Build the metadata object for a single `<package>` element, or `None` if it has
/// no usable package id.
fn xml_package_metadata(e: &BytesStart<'_>, guard: &mut XmlGuard) -> Option<Value> {
    let mut package: Option<String> = None;
    let mut code_path: Option<String> = None;
    let mut version: Option<String> = None;
    let mut user_id: Option<i64> = None;
    let mut ft: Option<String> = None;
    let mut it: Option<String> = None;
    let mut ut: Option<String> = None;
    let mut installer: Option<String> = None;
    let mut install_initiator: Option<String> = None;
    let mut update_owner: Option<String> = None;
    let mut orphaned: Option<String> = None;

    // The guard counts refused attributes itself, so the loop sees only the
    // ones that parsed; the running total is read back from it by the caller.
    for attr in guard.attributes(e) {
        let val = String::from_utf8_lossy(&attr.value).to_string();
        match attr.key.as_ref() {
            b"name" => package = Some(val),
            b"codePath" => code_path = Some(val),
            b"version" => version = Some(val),
            // userId is preferred; sharedUserId is a fallback if userId is absent.
            b"userId" => user_id = user_id.or_else(|| val.trim().parse::<i64>().ok()),
            b"sharedUserId" => user_id = user_id.or_else(|| val.trim().parse::<i64>().ok()),
            b"ft" => ft = Some(val),
            b"it" => it = Some(val),
            b"ut" => ut = Some(val),
            // The install provenance. `installer` is the package that asked
            // the package manager to install this one; the other two are
            // Android 14's finer split of the same question, absent on
            // earlier versions.
            b"installer" => installer = Some(val),
            b"installInitiator" => install_initiator = Some(val),
            b"updateOwner" => update_owner = Some(val),
            b"isOrphaned" => orphaned = Some(val),
            _ => {}
        }
    }

    let package = package.filter(|s| !s.is_empty())?;

    let mut m = Map::new();
    m.insert("type".into(), json!("InstalledApp"));
    m.insert("analysis_type".into(), json!("installed_app"));
    m.insert("subtype".into(), json!("InstalledApp"));
    m.insert("package".into(), json!(package));
    m.insert("name".into(), json!(package));
    let code_path = code_path.filter(|s| !s.is_empty());
    if let Some(cp) = &code_path {
        m.insert("code_path".into(), json!(cp));
    }
    if let Some(v) = version.filter(|s| !s.is_empty()) {
        m.insert("version".into(), json!(v));
    }
    if let Some(uid) = user_id {
        m.insert("user_id".into(), json!(uid));
    }
    if let Some((ms, rfc)) = ft.as_deref().and_then(decode_hex_timestamp) {
        m.insert("first_install".into(), json!(ms));
        m.insert("first_install_rfc3339".into(), json!(rfc));
    }
    if let Some((ms, rfc)) = it.as_deref().and_then(decode_hex_timestamp) {
        m.insert("install_time".into(), json!(ms));
        m.insert("install_time_rfc3339".into(), json!(rfc));
    }
    if let Some((ms, rfc)) = ut.as_deref().and_then(decode_hex_timestamp) {
        m.insert("update_time".into(), json!(ms));
        m.insert("update_time_rfc3339".into(), json!(rfc));
    }

    // --- how it got onto the device ---------------------------------------
    let partition = code_path.as_deref().map(code_partition);
    if let Some(partition) = partition {
        m.insert("code_partition".into(), json!(partition));
    }
    let installer = installer.filter(|s| !s.is_empty());
    if let Some(who) = &installer {
        m.insert("installer_package".into(), json!(who));
    }
    // Android 14 splits the question three ways. Read where present; on an
    // earlier device they are absent, and the record does not then invent an
    // equality with `installer`.
    if let Some(who) = install_initiator.filter(|s| !s.is_empty()) {
        m.insert("install_initiator_package".into(), json!(who));
    }
    if let Some(who) = update_owner.filter(|s| !s.is_empty()) {
        m.insert("update_owner_package".into(), json!(who));
    }
    if let Some(flag) = orphaned.filter(|s| !s.is_empty()) {
        m.insert("is_orphaned".into(), json!(flag == "true"));
        m.insert("is_orphaned_note".into(), json!(ORPHANED_NOTE));
    }
    match (&installer, partition) {
        (Some(_), _) => {
            m.insert("install_source".into(), json!("installer_recorded"));
        }
        (None, Some(p)) if read_only_partition(p) => {
            m.insert("install_source".into(), json!("shipped_with_the_os"));
            m.insert("install_source_note".into(), json!(SHIPPED_NOTE));
        }
        (None, Some("data")) => {
            m.insert("install_source".into(), json!("no_installer_recorded"));
            m.insert("install_source_note".into(), json!(NO_INSTALLER_NOTE));
        }
        // No installer and no code path to place it: the file did not say
        // enough for either reading, and that is the answer.
        (None, _) => {
            m.insert("install_source".into(), json!("not_recorded"));
        }
    }
    m.insert("source".into(), json!("packages.xml"));

    Some(Value::Object(m))
}

/// Parse `packages.list`, emitting one record per line.
fn parse_packages_list(content: &[u8], case_id: Uuid, parent_id: Uuid) -> Vec<Artifact> {
    let text = String::from_utf8_lossy(content);
    let mut apps = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // packageName userId debugFlag dataPath seinfo gids [...]
        let fields: Vec<&str> = line.split_whitespace().collect();
        let package = match fields.first() {
            Some(p) if !p.is_empty() => *p,
            _ => continue,
        };

        let mut m = Map::new();
        m.insert("type".into(), json!("InstalledApp"));
        m.insert("analysis_type".into(), json!("installed_app"));
        m.insert("subtype".into(), json!("InstalledApp"));
        m.insert("package".into(), json!(package));
        m.insert("name".into(), json!(package));
        if let Some(uid) = fields.get(1).and_then(|s| s.parse::<i64>().ok()) {
            m.insert("user_id".into(), json!(uid));
        }
        if let Some(dp) = fields.get(3).filter(|s| !s.is_empty()) {
            m.insert("data_path".into(), json!(*dp));
        }
        m.insert("source".into(), json!("packages.list"));

        apps.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
                .with_parent(parent_id),
        );
    }

    apps
}

/// What reading the iOS application-state database produced.
struct IosAppStateRead {
    apps: Vec<Artifact>,
    /// Why the inventory is not known to be the complete installed set, or
    /// `None` when every row was read.
    detail: Option<String>,
    /// The schema-drift markers the read owes: a version outside the validated
    /// range, or the identifier column no candidate resolved.
    stale: Vec<Artifact>,
}

impl IosAppStateRead {
    fn unread(detail: String) -> Self {
        Self {
            apps: Vec::new(),
            detail: Some(detail),
            stale: Vec::new(),
        }
    }
}

/// What one walk of `application_identifier_tab` yielded.
struct IosBundles {
    bundles: Vec<String>,
    /// Rows that would not decode: each is an installed application missing
    /// from the inventory.
    row_errors: u64,
    stale: Vec<Artifact>,
    /// Set when the identifier column did not resolve, so no row was read.
    unresolved: bool,
}

/// Parse iOS `applicationState.db`: the `application_identifier_tab` table lists
/// every installed app's bundle id. Emits one `InstalledApp` record per bundle.
///
/// A file this module already selected by name that cannot be staged, opened or
/// queried yields no apps — and an empty app list is read as "nothing was
/// installed on this device". Every such exit therefore carries a reason back to
/// the caller, which puts it on the summary record (B7-005).
fn parse_ios_app_state(
    content: &[u8],
    data: &dyn DataSource,
    case_id: Uuid,
    parent_id: Uuid,
) -> IosAppStateRead {
    if !looks_like_sqlite(content) {
        return IosAppStateRead::unread(
            "applicationState.db does not begin with the SQLite header; no app inventory \
             could be read from it"
                .to_string(),
        );
    }
    // Spill the `-wal` sibling with the database. A live applicationState.db
    // keeps its newest rows in an uncheckpointed WAL, and the main file alone
    // silently drops the most recently installed apps (BUG-256). TempDb removes
    // the spill (and its sidecars) on drop, even if the parse panics.
    let temp = match TempDb::write_with_sidecars(content, "appstate", data) {
        Ok(t) => t,
        Err(e) => {
            return IosAppStateRead::unread(format!(
                "applicationState.db could not be staged for reading: {}",
                e
            ))
        }
    };
    match read_ios_bundles(temp.path(), case_id, parent_id) {
        Ok(read) => {
            let apps = read
                .bundles
                .into_iter()
                .map(|b| ios_app_record(&b, case_id, parent_id))
                .collect();
            let detail = if read.unresolved {
                Some(
                    "no column of application_identifier_tab carries the application_identifier \
                     this parser reads, so no installed application was inventoried"
                        .to_string(),
                )
            } else {
                (read.row_errors > 0).then(|| {
                    format!(
                        "{} rows of application_identifier_tab could not be decoded",
                        read.row_errors
                    )
                })
            };
            IosAppStateRead {
                apps,
                detail,
                stale: read.stale,
            }
        }
        Err(e) => IosAppStateRead::unread(format!(
            "application_identifier_tab could not be queried: {}",
            e
        )),
    }
}

/// Read every non-empty bundle id from `application_identifier_tab`, plus the
/// number of rows that would not decode.
///
/// Undecodable rows are counted rather than dropped: each one is an installed
/// application missing from the inventory. The column is resolved before the
/// query is written, so a renamed identifier column is declared by name rather
/// than surfacing as a query error that reads like a broken file.
fn read_ios_bundles(
    path: &std::path::Path,
    case_id: Uuid,
    parent_id: Uuid,
) -> rusqlite::Result<IosBundles> {
    let conn = open_readonly(path)?;
    let mut stale: Vec<Artifact> = assess_version(
        &IOS_APPSTATE_SUPPORT,
        &single_row_version(&conn, "schema", "version"),
        case_id,
        parent_id,
    )
    .into_iter()
    .collect();
    // A column list that would not read is a query failure, and reported as
    // one: the caller's "could not be queried" detail carries the reason.
    let plan = plan_columns(
        &conn,
        "application_identifier_tab",
        IOS_APPSTATE_FIELDS,
        &[],
    )
    .map_err(|why| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
            Some(why),
        )
    })?;
    let Some(column) = plan.column("application_identifier") else {
        stale.push(unresolved_fields_marker(
            &IOS_APPSTATE_SUPPORT,
            "application_identifier_tab",
            &plan,
            0,
            case_id,
            parent_id,
        ));
        return Ok(IosBundles {
            bundles: Vec::new(),
            row_errors: 0,
            stale,
            unresolved: true,
        });
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT {column} FROM application_identifier_tab \
         WHERE {column} IS NOT NULL AND {column} <> '' ORDER BY {column}"
    ))?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut bundles = Vec::new();
    let mut row_errors = 0u64;
    for row in rows {
        match row {
            Ok(b) => bundles.push(b),
            Err(_) => row_errors += 1,
        }
    }
    Ok(IosBundles {
        bundles,
        row_errors,
        stale,
        unresolved: false,
    })
}

/// Build an `InstalledApp` record for an iOS bundle id.
fn ios_app_record(bundle: &str, case_id: Uuid, parent_id: Uuid) -> Artifact {
    let mut m = Map::new();
    m.insert("type".into(), json!("InstalledApp"));
    m.insert("analysis_type".into(), json!("installed_app"));
    m.insert("subtype".into(), json!("InstalledApp"));
    m.insert("platform".into(), json!("iOS"));
    m.insert("package".into(), json!(bundle));
    m.insert("name".into(), json!(bundle));
    m.insert("source".into(), json!("applicationState.db"));
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
        .with_parent(parent_id)
}

/// How completely the inventory file was read and walked.
struct InventoryRead {
    bytes_short: bool,
    parse_incomplete: bool,
    bytes_read: u64,
    declared_size: u64,
    /// Human-readable statement of what stopped the walk, when it stopped.
    parse_detail: Option<String>,
    /// The reason class for a parse that stopped, when the parser knows it
    /// better than the default `unresolved_structure` — an ABX document that
    /// simply ends is a short read of the structure, not a broken one.
    parse_reason: Option<IncompleteReason>,
    /// Byte offset the parse stopped at, when the parser can name one.
    parse_offset: Option<u64>,
    /// `"abx"` or `"text"` for `packages.xml`; `None` for the other sources.
    encoding: Option<&'static str>,
    /// ABX strings that were decoded with replacement characters.
    abx_lossy_strings: usize,
}

/// Build the `InstalledAppSummary` record.
///
/// Forensic meaning: `app_count` is the number of applications THIS TOOL
/// recovered from the inventory file. When `content_incomplete` is set the file
/// was not read or walked to its end, so the absence of an app from the case is
/// not evidence it was not installed on the device.
fn summary_record(
    case_id: Uuid,
    parent_id: Uuid,
    app_count: usize,
    source: &str,
    read: InventoryRead,
) -> Artifact {
    let mut m = Map::new();
    m.insert("type".into(), json!("InstalledAppSummary"));
    m.insert("subtype".into(), json!("installed_app_summary"));
    m.insert("app_count".into(), json!(app_count));
    m.insert("source".into(), json!(source));
    if let Some(encoding) = read.encoding {
        m.insert("encoding".into(), json!(encoding));
    }
    if read.abx_lossy_strings > 0 {
        // Not incompleteness — nothing is missing — but a name shown with a
        // replacement character is not the name the device holds, and a
        // report must not quote it as if it were.
        m.insert("abx_lossy_strings".into(), json!(read.abx_lossy_strings));
        m.insert(
            "abx_lossy_detail".into(),
            json!(format!(
                "{} string(s) in the ABX document were not valid UTF-8 and are shown with \
                 replacement characters; a package name so shown is an approximation of the \
                 bytes on the device",
                read.abx_lossy_strings
            )),
        );
    }
    if read.bytes_short || read.parse_incomplete {
        // The file-level reason outranks the parser's: a file that was not
        // read whole cannot have been parsed whole, whatever the parser says.
        let reason = if read.declared_size > MAX_CONTENT_BYTES {
            IncompleteReason::CapReached
        } else if read.bytes_short {
            IncompleteReason::ShortRead
        } else {
            read.parse_reason
                .unwrap_or(IncompleteReason::UnresolvedStructure)
        };
        m.insert("content_incomplete".into(), json!(true));
        m.insert("content_incomplete_reason".into(), json!(reason.as_str()));
        m.insert("input_truncated".into(), json!(read.bytes_short));
        m.insert("parse_stopped_early".into(), json!(read.parse_incomplete));
        if let Some(offset) = read.parse_offset {
            m.insert("parse_stopped_at_offset".into(), json!(offset));
        }
        m.insert("bytes_read".into(), json!(read.bytes_read));
        m.insert("declared_size".into(), json!(read.declared_size));
        m.insert("max_content_bytes".into(), json!(MAX_CONTENT_BYTES));
        if let Some(detail) = read.parse_detail.as_deref() {
            m.insert("incomplete_detail".into(), json!(detail));
        }
        // The count above is a listing, so it carries the listing-level pair as
        // well: a consumer reading only `app_count` must still see that the
        // inventory is short.
        m.insert("inventory_incomplete".into(), json!(true));
        m.insert("inventory_incomplete_reason".into(), json!(reason.as_str()));
        m.insert(
            "message".into(),
            json!("The app inventory was not read or parsed to its end; the app list is a floor, not the installed set"),
        );
    }
    m.insert(
        "name".into(),
        json!(format!("Installed apps: {} ({})", app_count, source)),
    );
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
        .with_parent(parent_id)
}

/// Decode a hex string of Unix epoch milliseconds to `(epoch_ms, rfc3339)`.
/// Returns `None` for empty, non-hex, non-positive, or absurdly large values.
fn decode_hex_timestamp(raw: &str) -> Option<(i64, String)> {
    let s = raw.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    let ms = i64::from_str_radix(s, 16).ok()?;
    if ms <= 0 || ms > MAX_PLAUSIBLE_EPOCH_MS {
        return None;
    }
    let dt = chrono::DateTime::from_timestamp_millis(ms)?;
    Some((ms, dt.to_rfc3339()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }
    use rusqlite::Connection;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    fn file_artifact(name: &str, content: &[u8]) -> Artifact {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(content.to_vec()));
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": name }),
        )
    }

    fn app_count(arts: &[Artifact]) -> usize {
        arts.iter()
            .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("InstalledApp"))
            .count()
    }

    fn find_app<'a>(arts: &'a [Artifact], package: &str) -> &'a Artifact {
        arts.iter()
            .find(|a| a.metadata.get("package").and_then(|v| v.as_str()) == Some(package))
            .expect("app record present")
    }

    #[test]
    fn packages_xml_two_entries_ignores_non_package() {
        // 2021-01-01T00:00:00Z in epoch ms, encoded as hex like Android does.
        let ms: i64 = 1_609_459_200_000;
        let ft_hex = format!("{:x}", ms);
        let xml = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <shared-user name="android.uid.system" userId="1000" />
  <package name="com.whatsapp" codePath="/data/app/com.whatsapp-1" ft="{ft}" it="{ft}" ut="{ft}" version="242001" userId="10123" />
  <package name="com.android.chrome" codePath="/data/app/com.android.chrome-2" ft="{ft}" version="500" userId="10098" />
  <permissions><item name="android.permission.INTERNET" /></permissions>
</packages>"#,
            ft = ft_hex
        );

        let art = file_artifact("packages.xml", xml.as_bytes());
        let parent = art.id;
        let out = InstalledAppsParser::new().process(&art).unwrap();

        // Two package elements -> two InstalledApp records (shared-user,
        // permissions and item are ignored).
        assert_eq!(app_count(&out), 2);

        let wa = find_app(&out, "com.whatsapp");
        assert_eq!(wa.parent_id, Some(parent));
        assert_eq!(wa.metadata["code_path"], json!("/data/app/com.whatsapp-1"));
        assert_eq!(wa.metadata["user_id"], json!(10123));
        assert_eq!(wa.metadata["version"], json!("242001"));
        assert_eq!(wa.metadata["first_install"], json!(ms));
        assert!(wa.metadata["first_install_rfc3339"]
            .as_str()
            .unwrap()
            .starts_with("2021-01-01T00:00:00"));
        assert_eq!(wa.metadata["source"], json!("packages.xml"));

        let chrome = find_app(&out, "com.android.chrome");
        assert_eq!(chrome.metadata["user_id"], json!(10098));
        // Chrome has no it/ut in this fixture -> those fields are omitted.
        assert!(chrome.metadata.get("update_time").is_none());

        // Exactly one summary describing the file.
        let summary = out
            .iter()
            .find(|a| {
                a.metadata.get("type").and_then(|v| v.as_str()) == Some("InstalledAppSummary")
            })
            .expect("summary present");
        assert_eq!(summary.metadata["app_count"], json!(2));
        assert_eq!(summary.metadata["source"], json!("packages.xml"));
    }

    #[test]
    fn packages_list_two_lines() {
        let list = "com.whatsapp 10123 0 /data/user/0/com.whatsapp default:targetSdkVersion=30 3003,3004,9997\n\
                    com.android.chrome 10098 0 /data/user/0/com.android.chrome default 3003,9997";

        let art = file_artifact("packages.list", list.as_bytes());
        let parent = art.id;
        let out = InstalledAppsParser::new().process(&art).unwrap();

        assert_eq!(app_count(&out), 2);

        let wa = find_app(&out, "com.whatsapp");
        assert_eq!(wa.parent_id, Some(parent));
        assert_eq!(wa.metadata["user_id"], json!(10123));
        assert_eq!(wa.metadata["data_path"], json!("/data/user/0/com.whatsapp"));
        assert_eq!(wa.metadata["source"], json!("packages.list"));

        let chrome = find_app(&out, "com.android.chrome");
        assert_eq!(
            chrome.metadata["data_path"],
            json!("/data/user/0/com.android.chrome")
        );
    }

    #[test]
    fn gating_rejects_unrelated_file() {
        let art = file_artifact("notes.txt", b"just some notes");
        let out = InstalledAppsParser::new().process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn gating_rejects_directory() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"<packages/>".to_vec()));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "packages.xml", "is_directory": true }),
        );
        let out = InstalledAppsParser::new().process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn gating_rejects_missing_data_source() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "packages.xml" }),
        );
        let out = InstalledAppsParser::new().process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn path_based_gating_matches_system_path() {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(
            b"<packages><package name=\"com.x\" userId=\"10001\"/></packages>".to_vec(),
        ));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "packages.xml.renamed", "path": "/data/system/packages.xml" }),
        );
        let out = InstalledAppsParser::new().process(&art).unwrap();
        assert_eq!(app_count(&out), 1);
    }

    #[test]
    fn malformed_and_short_input_does_not_panic() {
        // Truncated XML mid-attribute.
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", b"<packages><package name="))
            .unwrap();
        // No packages fully parsed, but still returns Ok (summary only).
        assert_eq!(app_count(&out), 0);

        // Single-byte garbage.
        let out2 = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", b"x"))
            .unwrap();
        assert_eq!(app_count(&out2), 0);

        // Empty content.
        let out3 = InstalledAppsParser::new()
            .process(&file_artifact("packages.list", b""))
            .unwrap();
        assert_eq!(app_count(&out3), 0);
    }

    #[test]
    fn absurd_hex_timestamp_is_dropped() {
        // ffffffffffffff is far beyond year 2100 -> dropped, not fabricated.
        let xml =
            r#"<packages><package name="com.a" ft="ffffffffffffff" userId="10005"/></packages>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml.as_bytes()))
            .unwrap();
        let a = find_app(&out, "com.a");
        assert!(a.metadata.get("first_install").is_none());
        assert!(a.metadata.get("first_install_rfc3339").is_none());
    }

    /// The inventory of a synthetic iOS applicationState.db, without the
    /// `schema(version)` row FrontBoard writes (1 on both real stores).
    const APPSTATE_INVENTORY_SQL: &str = "
        CREATE TABLE application_identifier_tab (id INTEGER PRIMARY KEY, application_identifier TEXT);
        INSERT INTO application_identifier_tab VALUES (1, 'com.apple.mobilesafari');
        INSERT INTO application_identifier_tab VALUES (2, 'net.whatsapp.WhatsApp');
        INSERT INTO application_identifier_tab VALUES (3, 'com.burbn.instagram');
        INSERT INTO application_identifier_tab VALUES (4, '');";

    fn appstate_db_from_sql(sql: &str) -> Vec<u8> {
        let temp_path = std::env::temp_dir().join(format!("test_appstate_{}.db", Uuid::new_v4()));
        {
            let conn = Connection::open(&temp_path).unwrap();
            conn.execute_batch(sql).unwrap();
        }
        let data = std::fs::read(&temp_path).unwrap();
        let _ = std::fs::remove_file(&temp_path);
        data
    }

    /// Build a synthetic iOS applicationState.db with a bundle-id inventory, at
    /// the validated schema version.
    fn create_ios_appstate_db() -> Vec<u8> {
        appstate_db_from_sql(&format!(
            "CREATE TABLE schema (version INT NOT NULL); INSERT INTO schema VALUES (1);
             {APPSTATE_INVENTORY_SQL}"
        ))
    }

    fn stale_markers(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["type"] == "ParserStaleWarning")
            .collect()
    }

    /// `schema.version` is 1 on both real stores (ios2022ffs and the macos2021
    /// tree); a store at that version with the inventory column present owes no
    /// stale marker.
    #[test]
    fn ios_appstate_at_the_validated_schema_version_carries_no_stale_marker() {
        let out = InstalledAppsParser::new()
            .process(&file_artifact(
                "applicationState.db",
                &create_ios_appstate_db(),
            ))
            .unwrap();
        assert!(stale_markers(&out).is_empty());
        assert_eq!(app_count(&out), 3);
    }

    /// A newer FrontBoard schema is still inventoried, and the parse says the
    /// version is past what was validated rather than presenting the list as
    /// checked.
    #[test]
    fn ios_appstate_with_a_newer_schema_version_is_parsed_and_declared_stale() {
        let db = appstate_db_from_sql(&format!(
            "CREATE TABLE schema (version INT NOT NULL); INSERT INTO schema VALUES (2);
             {APPSTATE_INVENTORY_SQL}"
        ));
        let out = InstalledAppsParser::new()
            .process(&file_artifact("applicationState.db", &db))
            .unwrap();
        assert_eq!(app_count(&out), 3, "the inventory is still read");
        let stale = stale_markers(&out);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].metadata["seen_schema_version"], 2);
        assert_eq!(stale[0].metadata["supported_range"], "1..=1");
        assert_eq!(stale[0].metadata["app"], "ios-applicationstate");
        // §1.4a (decided 2026-09-26): outside the range is a disclosure.
        assert_eq!(stale[0].metadata["status"], "SchemaOutsideValidated");
        assert!(stale[0].metadata.get("content_incomplete").is_none());
        assert!(stale[0].metadata.get("content_incomplete_reason").is_none());
        // The summary counts applications, not markers.
        let summary = out
            .iter()
            .find(|a| a.metadata["type"] == "InstalledAppSummary")
            .unwrap();
        assert_eq!(summary.metadata["app_count"], 3);
    }

    /// A store with no `schema` table is stated as carrying no version — never
    /// as version 0, older than 1.
    #[test]
    fn ios_appstate_without_a_schema_table_is_stated_not_ranked() {
        let out = InstalledAppsParser::new()
            .process(&file_artifact(
                "applicationState.db",
                &appstate_db_from_sql(APPSTATE_INVENTORY_SQL),
            ))
            .unwrap();
        assert_eq!(app_count(&out), 3);
        let stale = stale_markers(&out);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].metadata["status"], "SchemaVersionNotRecorded");
        assert!(stale[0].metadata.get("content_incomplete").is_none());
    }

    /// A renamed `application_identifier` would otherwise be "no apps were
    /// installed". The marker names the field; the summary says zero apps
    /// were recovered and why.
    #[test]
    fn ios_appstate_with_a_renamed_identifier_column_names_it_on_the_stale_marker() {
        let db = appstate_db_from_sql(
            "CREATE TABLE schema (version INT NOT NULL); INSERT INTO schema VALUES (1);
             CREATE TABLE application_identifier_tab (id INTEGER PRIMARY KEY, bundle_id TEXT);
             INSERT INTO application_identifier_tab VALUES (1, 'com.apple.mobilesafari');",
        );
        let out = InstalledAppsParser::new()
            .process(&file_artifact("applicationState.db", &db))
            .unwrap();
        assert_eq!(app_count(&out), 0);
        let stale = stale_markers(&out);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].metadata["status"], "SchemaFieldsUnresolved");
        assert_eq!(
            stale[0].metadata["unresolved_fields"],
            json!(["application_identifier"])
        );
        assert_eq!(
            stale[0].metadata["source_table"],
            "application_identifier_tab"
        );
        assert_eq!(
            stale[0].metadata["present_columns"],
            json!(["bundle_id", "id"])
        );
        let summary = out
            .iter()
            .find(|a| a.metadata["type"] == "InstalledAppSummary")
            .unwrap();
        assert_eq!(summary.metadata["app_count"], 0);
        assert_eq!(summary.metadata["content_incomplete"], json!(true));
        assert!(summary.metadata["incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("application_identifier"));
    }

    #[test]
    fn ios_appstate_lists_bundle_ids() {
        let db = create_ios_appstate_db();
        let out = InstalledAppsParser::new()
            .process(&file_artifact("applicationState.db", &db))
            .unwrap();
        // Three real bundles; the empty identifier is skipped.
        assert_eq!(app_count(&out), 3);
        let wa = find_app(&out, "net.whatsapp.WhatsApp");
        assert_eq!(wa.metadata["platform"], "iOS");
        assert_eq!(wa.metadata["source"], "applicationState.db");
        assert!(out.iter().any(
            |a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("InstalledAppSummary")
        ));
    }

    #[test]
    fn ios_appstate_reads_uncheckpointed_wal_rows() {
        // A live applicationState.db holds its newest rows in an uncheckpointed
        // WAL; spilling the main database alone drops them (BUG-256).
        use seance_core::data_source::SiblingBundleSource;
        use std::collections::HashMap;

        let path = std::env::temp_dir().join(format!("seance_appstate_wal_{}.db", Uuid::new_v4()));
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE application_identifier_tab (id INTEGER PRIMARY KEY, application_identifier TEXT);
             INSERT INTO application_identifier_tab VALUES (1, 'com.apple.mobilesafari');",
        )
        .unwrap();
        // From here on, rows land only in the WAL.
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "wal_autocheckpoint", 0i64)
            .unwrap();
        conn.execute_batch(
            "INSERT INTO application_identifier_tab VALUES (2, 'net.whatsapp.WhatsApp');",
        )
        .unwrap();
        let db_bytes = std::fs::read(&path).unwrap();
        let wal_bytes = std::fs::read(format!("{}-wal", path.display())).unwrap();
        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        assert!(!wal_bytes.is_empty(), "the fixture WAL must hold frames");

        // Without the sibling: only the checkpointed app.
        let without = InstalledAppsParser::new()
            .process(&file_artifact("applicationState.db", &db_bytes))
            .unwrap();
        assert_eq!(app_count(&without), 1);

        // With the `-wal` reachable through the data source: both apps.
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(db_bytes));
        let wal: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(wal_bytes));
        let mut siblings = HashMap::new();
        siblings.insert("-wal".to_string(), wal);
        let bundled: Arc<dyn DataSource> = Arc::new(SiblingBundleSource::new(inner, siblings));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(bundled),
            json!({ "name": "applicationState.db" }),
        );
        let with = InstalledAppsParser::new().process(&art).unwrap();
        assert_eq!(app_count(&with), 2);
        find_app(&with, "net.whatsapp.WhatsApp");
    }

    #[test]
    fn ios_appstate_non_sqlite_is_ignored() {
        // A file named applicationState.db that isn't SQLite yields no apps and
        // never panics.
        let out = InstalledAppsParser::new()
            .process(&file_artifact("applicationState.db", b"not a database"))
            .unwrap();
        assert_eq!(app_count(&out), 0);
    }

    /// B7-005: an `applicationState.db` that cannot be read must not summarise
    /// as a device with zero installed apps. The summary has to say the
    /// inventory was never read.
    #[test]
    fn ios_appstate_unreadable_summary_is_marked_incomplete() {
        let out = InstalledAppsParser::new()
            .process(&file_artifact("applicationState.db", b"not a database"))
            .unwrap();
        let summary = out
            .iter()
            .find(|a| a.metadata["type"] == "InstalledAppSummary")
            .expect("a summary is always emitted");
        assert_eq!(summary.metadata["app_count"], json!(0));
        assert_eq!(summary.metadata["content_incomplete"], json!(true));
        assert_eq!(
            summary.metadata["content_incomplete_reason"],
            json!("unresolved_structure"),
        );
        assert_eq!(summary.metadata["inventory_incomplete"], json!(true));
        assert!(summary.metadata["incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("SQLite header"));
    }

    // --- Inventory completeness honesty (B2-087) --------------------------

    fn summary_of(out: &[Artifact]) -> &Artifact {
        out.iter()
            .find(|a| a.metadata["type"] == "InstalledAppSummary")
            .expect("summary record")
    }

    /// A fully read, fully parsed inventory must not claim to be incomplete.
    #[test]
    fn a_complete_inventory_summary_is_not_marked_incomplete() {
        let xml = br#"<packages><package name="com.example.a" userId="10001"/></packages>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml))
            .unwrap();
        let s = summary_of(&out);
        assert_eq!(s.metadata["app_count"], json!(1));
        assert!(s.metadata.get("content_incomplete").is_none());
    }

    /// An inventory read short of its declared size reports a floor, not the
    /// installed set.
    #[test]
    fn a_short_read_inventory_summary_is_marked_incomplete() {
        let xml = br#"<packages><package name="com.example.a" userId="10001"/></packages>"#;
        let declared = xml.len() as u64 + 4096;
        use seance_core::test_support::TruncatedSource;
        let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(xml.to_vec(), declared));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "packages.xml" }),
        );
        let out = InstalledAppsParser::new().process(&art).unwrap();
        let s = summary_of(&out);
        assert_eq!(s.metadata["content_incomplete"], json!(true));
        assert_eq!(s.metadata["content_incomplete_reason"], "short_read");
        assert_eq!(s.metadata["input_truncated"], json!(true));
        assert_eq!(s.metadata["declared_size"], json!(declared));
    }

    /// XML that breaks mid-document stops the walk; the packages after the break
    /// are never seen, so the summary must say the parse stopped early.
    #[test]
    fn an_inventory_whose_xml_breaks_mid_file_is_marked_incomplete() {
        // A mismatched end tag after the first package aborts the event stream;
        // any packages that would have followed are never seen.
        let xml = br#"<packages><package name="com.example.a" userId="10001"/></wrong>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml))
            .unwrap();
        let s = summary_of(&out);
        assert_eq!(s.metadata["content_incomplete"], json!(true));
        assert_eq!(s.metadata["parse_stopped_early"], json!(true));
    }

    /// RUSTSEC-2026-0194 regression at the plugin boundary.
    ///
    /// `packages.xml` is read off the device under examination, so a crafted
    /// `<package>` element is ordinary hostile input. Unguarded, 200,000
    /// attributes on one element costs roughly 29 seconds.
    #[test]
    fn a_package_with_a_hostile_attribute_count_parses_in_bounded_time() {
        let mut xml = String::from("<packages><package");
        for i in 0..200_000 {
            xml.push_str(&format!(" a{i}=\"v\""));
        }
        xml.push_str(" name=\"com.example\"/></packages>");

        let start = std::time::Instant::now();
        let PackagesXmlRead {
            apps,
            stopped_early: stopped,
            guard,
            ..
        } = parse_packages_xml(xml.as_bytes(), Uuid::new_v4(), Uuid::new_v4());
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "parsing took {elapsed:?}; unguarded this costs ~29 s, so the bounded \
             reader is not in this path"
        );
        assert!(
            !stopped,
            "the document is well-formed; it was not truncated"
        );
        assert!(
            guard.attributes_truncated(),
            "the cap must have engaged on an element with 200,000 attributes"
        );
        // `name` sits past the cap, so this package has no usable id and is
        // dropped -- which the caller reports rather than presenting a short
        // inventory as the installed set.
        assert!(
            apps.is_empty(),
            "a package whose name attribute was refused cannot be inventoried"
        );
    }

    /// The ordinary case stays untouched by the guard.
    #[test]
    fn an_ordinary_packages_xml_reports_no_anomaly() {
        let xml = br#"<packages><package name="com.example" codePath="/data/app"/></packages>"#;
        let PackagesXmlRead {
            apps,
            stopped_early: stopped,
            guard,
            encoding,
            ..
        } = parse_packages_xml(xml, Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(apps.len(), 1);
        assert!(!stopped);
        assert_eq!(encoding, "text");
        assert!(!guard.attributes_truncated());
        assert_eq!(guard.attribute_errors(), 0);
        assert!(guard.describe().is_empty());
    }

    // --- Android Binary XML (HUNT-069) ------------------------------------

    /// The install time Josh Hickman's Android 14 image records for one
    /// package, as the ABX `LONG_HEX` it is stored as and as the text hex
    /// string an Android 11 device would have written.
    const IT_HEX_TEXT: &str = "18d46e9f2f8";
    const IT_LONG_HEX: i64 = 0x018D_46E9_F2F8;

    /// A `packages.xml` in ABX, shaped as `Settings.writeLPr` shapes it:
    /// `ft`/`it`/`ut` as `LONG_HEX`, `version` as `LONG`, `userId` as `INT`.
    fn abx_packages_xml() -> Vec<u8> {
        use seance_xml_util::abx::fixture::AbxWriter;
        AbxWriter::new()
            .start_tag("packages")
            .start_tag("version")
            .attr_int("sdkVersion", 34)
            .attr_int("databaseVersion", 3)
            .end_tag("version")
            .start_tag("package")
            .attr_str("name", "com.whatsapp")
            .attr_str("codePath", "/data/app/~~abc==/com.whatsapp-xyz==")
            .attr_long_hex("ft", IT_LONG_HEX)
            .attr_long_hex("it", IT_LONG_HEX)
            .attr_long_hex("ut", IT_LONG_HEX)
            .attr_long("version", 242_001)
            .attr_int("userId", 10123)
            .attr_bool("isStopped", false)
            .start_tag("sigs")
            .attr_int("count", 1)
            .end_tag("sigs")
            .end_tag("package")
            .start_tag("package")
            .attr_str("name", "com.android.chrome")
            .attr_str("codePath", "/data/app/~~def==/com.android.chrome-uvw==")
            .attr_long_hex("ft", IT_LONG_HEX)
            .attr_long("version", 500)
            .attr_int("userId", 10098)
            .end_tag("package")
            .end_tag("packages")
            .end_document()
            .finish()
    }

    /// The same inventory as an Android 11 device would have written it.
    fn text_packages_xml() -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <version sdkVersion="34" databaseVersion="3" />
  <package name="com.whatsapp" codePath="/data/app/~~abc==/com.whatsapp-xyz==" ft="{it}" it="{it}" ut="{it}" version="242001" userId="10123" isStopped="false"><sigs count="1" /></package>
  <package name="com.android.chrome" codePath="/data/app/~~def==/com.android.chrome-uvw==" ft="{it}" version="500" userId="10098" />
</packages>"#,
            it = IT_HEX_TEXT
        )
    }

    /// Android 12+ writes `packages.xml` as ABX. Read as text it yields zero
    /// packages; decoded, it must yield exactly what the text form of the
    /// same inventory yields, install times included.
    #[test]
    fn an_abx_packages_xml_yields_the_same_apps_and_install_times_as_the_text_form() {
        let abx_out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", &abx_packages_xml()))
            .unwrap();
        let text_out = InstalledAppsParser::new()
            .process(&file_artifact(
                "packages.xml",
                text_packages_xml().as_bytes(),
            ))
            .unwrap();

        assert_eq!(app_count(&abx_out), 2);
        assert_eq!(app_count(&text_out), 2);

        for package in ["com.whatsapp", "com.android.chrome"] {
            let a = &find_app(&abx_out, package).metadata;
            let t = &find_app(&text_out, package).metadata;
            for field in [
                "package",
                "code_path",
                "version",
                "user_id",
                "first_install",
                "first_install_rfc3339",
                "install_time",
                "install_time_rfc3339",
                "update_time",
                "update_time_rfc3339",
                "source",
            ] {
                assert_eq!(a.get(field), t.get(field), "{package}.{field}");
            }
        }
        let wa = &find_app(&abx_out, "com.whatsapp").metadata;
        assert_eq!(wa["install_time"], json!(IT_LONG_HEX));
        assert_eq!(wa["install_time"], json!(1_706_291_753_720_i64));
        assert!(wa["install_time_rfc3339"]
            .as_str()
            .unwrap()
            .starts_with("2024-01-26T17:55:53"));

        let abx_summary = summary_of(&abx_out);
        assert_eq!(abx_summary.metadata["app_count"], json!(2));
        assert_eq!(abx_summary.metadata["encoding"], json!("abx"));
        assert!(
            abx_summary.metadata.get("content_incomplete").is_none(),
            "a whole ABX document is a whole inventory"
        );
        assert_eq!(summary_of(&text_out).metadata["encoding"], json!("text"));
    }

    /// An ABX `packages.xml` cut mid-file keeps the packages before the cut
    /// and says, with the byte offset, that the rest were never seen.
    #[test]
    fn a_truncated_abx_packages_xml_stamps_the_summary_incomplete_with_the_offset() {
        let whole = abx_packages_xml();
        // Cut inside the second package's name string, after the first
        // package is complete.
        let chrome_at = whole
            .windows(18)
            .position(|w| w == b"com.android.chrome")
            .expect("fixture holds the second package");
        let cut = chrome_at + 6;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", &whole[..cut]))
            .unwrap();

        assert_eq!(app_count(&out), 1, "the package before the cut survives");
        find_app(&out, "com.whatsapp");

        let s = summary_of(&out);
        assert_eq!(s.metadata["encoding"], json!("abx"));
        assert_eq!(s.metadata["content_incomplete"], json!(true));
        assert_eq!(s.metadata["content_incomplete_reason"], json!("short_read"));
        assert_eq!(s.metadata["inventory_incomplete"], json!(true));
        assert_eq!(s.metadata["parse_stopped_early"], json!(true));
        // The string's length prefix was read; its bytes begin at chrome_at.
        assert_eq!(s.metadata["parse_stopped_at_offset"], json!(chrome_at));
        let detail = s.metadata["incomplete_detail"].as_str().unwrap();
        assert!(
            detail.contains(&format!("byte {chrome_at}")),
            "the detail names the offset: {detail}"
        );
        assert!(
            detail.contains("ABX"),
            "the detail names the encoding: {detail}"
        );
    }

    /// ABX bytes that do not form a document — not merely a short one — are
    /// an unresolved structure, not a short read, so an examiner is not told
    /// to go and find the rest of a file that has no rest.
    #[test]
    fn a_corrupt_abx_packages_xml_is_an_unresolved_structure_not_a_short_read() {
        // Header, START_DOCUMENT, then a START_TAG naming interned string 9
        // in an empty table.
        let bytes = b"ABX\0\x10\x32\x00\x09";
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", bytes))
            .unwrap();
        assert_eq!(app_count(&out), 0);
        let s = summary_of(&out);
        assert_eq!(s.metadata["encoding"], json!("abx"));
        assert_eq!(s.metadata["content_incomplete"], json!(true));
        assert_eq!(
            s.metadata["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(s.metadata["parse_stopped_at_offset"], json!(6));
    }

    /// A string the decoder could only approximate is disclosed on the
    /// summary: the package name shown is then not the name the device holds.
    #[test]
    fn an_abx_string_that_is_not_utf8_is_disclosed_on_the_summary() {
        use seance_xml_util::abx::fixture::AbxWriter;
        let bytes = AbxWriter::new()
            .start_tag("packages")
            .start_tag("package")
            .attr_str_bytes("name", b"com.\xed\xa0\x80bad")
            .end_tag("package")
            .end_tag("packages")
            .end_document()
            .finish();
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", &bytes))
            .unwrap();
        find_app(&out, "com.\u{FFFD}bad");
        let s = summary_of(&out);
        assert_eq!(s.metadata["abx_lossy_strings"], json!(1));
        assert!(s.metadata["abx_lossy_detail"]
            .as_str()
            .unwrap()
            .contains("replacement"));
    }

    // --- how a package got onto the device -----------------------------------

    /// The question this reads for: which app asked the package manager to
    /// install this one.
    #[test]
    fn a_play_store_install_names_the_store_that_installed_it() {
        let xml = br#"<packages>
  <package name="com.discord" codePath="/data/app/com.discord-1" installer="com.android.vending" userId="10200"/>
</packages>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml))
            .unwrap();
        let app = find_app(&out, "com.discord");
        assert_eq!(
            app.metadata["installer_package"],
            json!("com.android.vending")
        );
        assert_eq!(app.metadata["install_source"], json!("installer_recorded"));
        assert_eq!(app.metadata["code_partition"], json!("data"));
        // Nothing is inferred here, so no note is attached.
        assert!(app.metadata.get("install_source_note").is_none());
    }

    /// And the one it exists to surface — with the caution that makes it usable.
    #[test]
    fn a_data_partition_package_with_no_installer_is_reported_as_the_signal_it_is() {
        let xml = br#"<packages>
  <package name="com.topjohnwu.magisk" codePath="/data/app/com.topjohnwu.magisk-1" userId="10300"/>
</packages>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml))
            .unwrap();
        let app = find_app(&out, "com.topjohnwu.magisk");
        assert!(app.metadata.get("installer_package").is_none());
        assert_eq!(
            app.metadata["install_source"],
            json!("no_installer_recorded")
        );
        let note = app.metadata["install_source_note"]
            .as_str()
            .expect("a note");
        assert!(note.contains("signal a sideload leaves"), "{note}");
        assert!(
            note.contains("SIGNAL AND NOT A PROOF"),
            "an absent attribute has other explanations and the record must carry them: {note}"
        );
        assert!(note.contains("restored from a backup"), "{note}");
    }

    /// The distinction without which the signal is noise: on a real device
    /// most packages have no installer because nothing installed them.
    #[test]
    fn a_system_package_with_no_installer_is_not_reported_as_a_sideload() {
        let xml = br#"<packages>
  <package name="com.android.settings" codePath="/system/priv-app/Settings" userId="1000"/>
  <package name="com.qti.diagservices" codePath="/vendor/app/diag" userId="1001"/>
  <package name="com.google.android.gsf" codePath="/product/app/GoogleServices" userId="1002"/>
</packages>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml))
            .unwrap();
        for (package, partition) in [
            ("com.android.settings", "system"),
            ("com.qti.diagservices", "vendor"),
            ("com.google.android.gsf", "product"),
        ] {
            let app = find_app(&out, package);
            assert_eq!(app.metadata["code_partition"], json!(partition));
            assert_eq!(
                app.metadata["install_source"],
                json!("shipped_with_the_os"),
                "{package} is on a read-only OS partition"
            );
            let note = app.metadata["install_source_note"]
                .as_str()
                .expect("a note");
            assert!(note.contains("NOT a sideload signal"), "{note}");
        }
    }

    #[test]
    fn a_package_with_neither_an_installer_nor_a_code_path_claims_nothing() {
        // Neither reading is available, so the answer is that the file did not
        // say — not the sideload label, which would be an invention.
        let xml = br#"<packages><package name="com.example.a" userId="10001"/></packages>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml))
            .unwrap();
        let app = find_app(&out, "com.example.a");
        assert_eq!(app.metadata["install_source"], json!("not_recorded"));
        assert!(app.metadata.get("install_source_note").is_none());
        assert!(app.metadata.get("code_partition").is_none());
    }

    #[test]
    fn android_fourteens_finer_split_is_read_where_the_device_wrote_it() {
        // Android 14 records who initiated the install and who owns updates
        // separately from the installing package. An earlier device writes
        // none of them, and the record then carries none.
        let xml = br#"<packages>
  <package name="com.example.new" codePath="/data/app/com.example.new-1"
           installer="com.android.vending" installInitiator="com.android.vending"
           updateOwner="com.android.vending" userId="10400"/>
  <package name="com.example.old" codePath="/data/app/com.example.old-1"
           installer="com.android.vending" userId="10401"/>
</packages>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml))
            .unwrap();
        let modern = find_app(&out, "com.example.new");
        assert_eq!(
            modern.metadata["install_initiator_package"],
            json!("com.android.vending")
        );
        assert_eq!(
            modern.metadata["update_owner_package"],
            json!("com.android.vending")
        );
        let older = find_app(&out, "com.example.old");
        assert!(older.metadata.get("install_initiator_package").is_none());
        assert!(older.metadata.get("update_owner_package").is_none());
    }

    #[test]
    fn the_orphaned_flag_is_reported_and_not_interpreted() {
        let xml = br#"<packages>
  <package name="com.example.a" codePath="/data/app/a-1" installer="com.android.vending" isOrphaned="true" userId="10001"/>
  <package name="com.example.b" codePath="/data/app/b-1" installer="com.android.vending" userId="10002"/>
</packages>"#;
        let out = InstalledAppsParser::new()
            .process(&file_artifact("packages.xml", xml))
            .unwrap();
        let flagged = find_app(&out, "com.example.a");
        assert_eq!(flagged.metadata["is_orphaned"], json!(true));
        assert!(flagged.metadata["is_orphaned_note"]
            .as_str()
            .expect("a note")
            .contains("NOT established"));
        // Absent means the file did not write it, which is not `false`.
        assert!(find_app(&out, "com.example.b")
            .metadata
            .get("is_orphaned")
            .is_none());
    }

    #[test]
    fn a_code_path_is_placed_by_its_partition_and_an_unknown_one_says_so() {
        assert_eq!(code_partition("/data/app/com.a-1"), "data");
        assert_eq!(code_partition("/system/priv-app/Settings"), "system");
        assert_eq!(code_partition("/system_ext/app/Thing"), "system");
        assert_eq!(code_partition("/product/app/Thing"), "product");
        assert_eq!(code_partition("/vendor/app/Thing"), "vendor");
        assert_eq!(code_partition("/apex/com.android.thing"), "apex");
        // A path this reader does not recognise is not filed as user data,
        // because that is the reading the sideload signal rests on. An
        // adopted SD card lands here, and calling it `data` would put a
        // package the device installed normally under the signal.
        assert_eq!(code_partition("/mnt/expand/abcd/app/com.a-1"), "other");
        assert_eq!(code_partition(""), "other");
        assert!(!read_only_partition("data"));
        assert!(!read_only_partition("other"));
    }

    /// The real device, where the signal is one package in 213.
    #[test]
    fn the_real_android_packages_xml_finds_the_one_sideloaded_app() {
        let path = home("ctf-evidence/android2022/tree/data/system/packages.xml");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!(
                "skipping: {} is not present. Recreate it with: mkdir -p \
                 ~/ctf-evidence/android2022/tree && cd \
                 ~/ctf-evidence/android2022/tree && tar xf ../android.tar \
                 data/system",
                path.display()
            );
            return;
        };
        assert_eq!(bytes.len(), 1_145_741);
        // The artifact shape a directory walk produces: the basename in
        // `name` and the full path beside it.
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": "packages.xml", "path": "/data/system/packages.xml" }),
        );
        let out = InstalledAppsParser::new().process(&artifact).unwrap();
        let apps: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["type"] == "InstalledApp")
            .collect();
        assert_eq!(apps.len(), 213);

        // The census this attribute makes possible.
        let mut recorded = 0usize;
        let mut shipped = 0usize;
        let mut unrecorded: Vec<&str> = Vec::new();
        for app in &apps {
            match app.metadata["install_source"].as_str() {
                Some("installer_recorded") => recorded += 1,
                Some("shipped_with_the_os") => shipped += 1,
                Some("no_installer_recorded") => {
                    unrecorded.push(app.metadata["package"].as_str().unwrap_or_default())
                }
                other => panic!("unexpected install_source {other:?}"),
            }
        }
        assert_eq!(recorded, 62, "and every one of them the Play Store");
        assert!(apps
            .iter()
            .filter(|a| a.metadata["install_source"] == "installer_recorded")
            .all(|a| a.metadata["installer_package"] == "com.android.vending"));
        assert_eq!(
            shipped, 150,
            "150 packages are on read-only OS partitions, so their missing installer means \
             nothing installed them — without that distinction the finding below is 151 \
             packages of noise"
        );

        // And the finding: one package in 213 has its code in user data and no
        // installer recorded, on a device where the other 62 all name the
        // Play Store.
        assert_eq!(
            unrecorded,
            vec!["com.topjohnwu.magisk"],
            "the one data-partition package the package manager recorded no installer for — \
             Magisk, an Android rooting tool"
        );
        let magisk = find_app(&out, "com.topjohnwu.magisk");
        assert_eq!(magisk.metadata["code_partition"], json!("data"));
        assert!(magisk.metadata.get("installer_package").is_none());
        assert!(magisk.metadata["install_source_note"]
            .as_str()
            .expect("a note")
            .contains("SIGNAL AND NOT A PROOF"));

        // This device's Android version writes `it`, so the install times are
        // there — which is what makes their absence a version fact elsewhere.
        assert!(magisk.metadata.get("install_time_rfc3339").is_some());
        // And none of the 213 carries Android 14's finer split, so nothing
        // here grades those two attributes.
        assert!(apps
            .iter()
            .all(|a| a.metadata.get("install_initiator_package").is_none()));
        assert!(apps
            .iter()
            .all(|a| a.metadata.get("update_owner_package").is_none()));
    }
}
