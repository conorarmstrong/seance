#![forbid(unsafe_code)]
//! Login accounting: Linux `utmp`, `wtmp`, `btmp` and `lastlog`, and macOS
//! `utmpx`.
//!
//! These files are the native answer to "who was on this machine, from where,
//! and when":
//!
//! | File | Records | Question it answers |
//! |------|---------|---------------------|
//! | `/var/run/utmp` | sessions open right now | Who was logged in when the image was taken? |
//! | `/var/log/wtmp` | login/logout history, boots, shutdowns | Who logged in and out, from where, and when did the box reboot? |
//! | `/var/log/btmp` | **failed** login attempts | Who tried and failed — brute force, spraying, credential stuffing? |
//! | `/var/log/lastlog` | per-UID last successful login | When did each account last log in? |
//! | `/private/var/run/utmpx` (macOS) | sessions open right now | Who was logged in at the console and on which terminals? |
//!
//! macOS is the same *shape* of evidence in a different record: `struct utmpx`
//! is 628 bytes, puts its strings first, and reads its `ut_type` against a
//! different enumeration in which two of the values mean the opposite of what
//! they mean on Linux. Both the layout and that enumeration are detected, never
//! assumed — see [`UtmpLayout`] and [`TypeDialect`]. macOS keeps no `btmp`
//! equivalent and, since 10.5, no on-disk `wtmpx` or `lastlogx`: that history
//! moved into the Apple System Log, which this module does not read.
//!
//! [`UtmpParser`] is the [`ForensicsModule`] that produces them. It subscribes
//! to `FileEntry`, `FileContent` and `SystemArtifact`, so every file a
//! filesystem parser walks is offered to it; selection is by **content**
//! (record structure and field sanity) with the filename supplying only the
//! role, because the three `struct utmp` files are byte-for-byte identical and
//! nothing in a record says "this attempt failed".
//!
//! One file does state something about itself: a macOS `utmpx` opens with a
//! `SIGNATURE` record carrying the literal `utmpx-1.00`, which is reported as
//! `format_version` on the status row. It is the only corroboration of a
//! chosen layout in this family that comes from content rather than from field
//! plausibility.
//!
//! Emitted records — `LoginSession`, `FailedLogin`, `BootEvent`, `LastLogin`
//! and a `UtmpParseStatus` provenance row — plus one `TimelineEvent` per dated
//! record. Timestamps are UTC Unix seconds, which is what the kernel writes; no
//! timezone conversion is applied, and a record whose stored time is not a
//! plausible date produces no timeline row at all rather than a fabricated one
//! in 1970.
//!
//! Fail-closed behaviour an examiner should rely on:
//!
//! * The record stride is *detected* from the data, never assumed: a file whose
//!   size is not a whole number of records of a **known** layout is only
//!   accepted at a stride that additionally clears a stricter field-sanity
//!   threshold, and the leftover bytes are reported as a truncated tail.
//! * A file that our caps or thresholds turned away is reported with the reason
//!   (`UtmpParseStatus`) whenever its name claimed it was login accounting —
//!   "there was nothing here" and "we did not read this" never look the same.
//! * Every cap that bites is stamped on the artifacts it truncated.

mod record;
mod sessions;
#[cfg(test)]
mod tests;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::{read_capped, read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use tracing::{debug, warn};
use uuid::Uuid;

pub use record::{
    decode_addr, decode_lastlog, decode_utmp, detect, plausible_unix, role_hint, ut_type_name,
    DetectFailure, Detected, Endian, LastlogDetection, LastlogLayout, LastlogRecord, RecordReject,
    RoleHint, SanityFault, TypeDialect, UtmpDetection, UtmpLayout, UtmpRecord, UtmpRole,
    DARWIN_UTMPX_628, GLIBC_UTMP_384, LASTLOG_28, LASTLOG_292, MUSL_UTMPX_400,
};
pub use sessions::{
    classify, humanize_duration, reconstruct, BootEvent, ClosedBy, LoginSession, Reconstruction,
    RecordKind, SessionStatus,
};

use sessions::{boot_event, timeline_desc};

/// Ceiling on how much of a `utmp`/`wtmp`/`btmp` file is read into memory. A
/// real one is kilobytes to a few megabytes; the cap exists so a corrupt or
/// hostile size cannot exhaust a worker. Hitting it truncates the parse, which
/// is always reported as `content_incomplete`.
pub const MAX_UTMP_BYTES: u64 = 256 * 1024 * 1024;

/// Bytes read from the head of a file to decide what it is. 64 KiB covers ~170
/// glibc records, far more than the detector samples.
pub const DETECT_BYTES: u64 = 64 * 1024;

/// Hard ceiling on records decoded from one `utmp`-family file.
pub const MAX_UTMP_RECORDS: usize = 1_000_000;

/// Hard ceiling on reconstructed sessions from one file.
pub const MAX_SESSIONS: usize = 200_000;

/// Highest UID index walked in a `lastlog`. The file is indexed by UID and is
/// sparse: an LDAP-joined host with UIDs in the millions produces a multi-GB
/// file that is almost entirely holes, so iteration is bounded and the file is
/// streamed rather than buffered.
pub const MAX_LASTLOG_RECORDS: u64 = 5_000_000;

/// Ceiling on `LastLogin` records emitted from one `lastlog`.
pub const MAX_LASTLOG_EMIT: usize = 200_000;

/// UID records read per `read_at` while streaming a `lastlog`.
const LASTLOG_BLOCK_RECORDS: u64 = 512;

/// Module id, also written to every timeline row as `source_module`.
const MODULE_ID: &str = "plugin.linux.utmp";

/// The Linux login-accounting parser.
///
/// Register one instance with the orchestrator (`register_module`) in each
/// binary that ingests evidence; the orchestrator then hands it every
/// `FileEntry`/`FileContent`/`SystemArtifact` and it self-selects on content.
pub struct UtmpParser;

impl ForensicsModule for UtmpParser {
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
            ArtifactType::SystemArtifact,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        // Bounded `read_at` / `read_capped` only; nothing here needs a path on
        // disk, so no artifact is ever spilled to a temp file for us.
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Corrupt evidence must not fail the pipeline: every refusal is a value
        // (an empty vec, or a status record naming the reason), never an Err.
        Ok(parse(artifact))
    }
}

// --- entry point -------------------------------------------------------------

/// Parse one artifact, returning the records and timeline events it yields.
///
/// Returns an empty vector for the overwhelming majority of files, which are
/// not login accounting and whose names never claimed to be.
pub(crate) fn parse(artifact: &Artifact) -> Vec<Artifact> {
    parse_with_limits(artifact, Limits::production())
}

/// [`parse`] under explicit caps.
///
/// The caps are a parameter so the production code path — not a stand-in — can
/// be driven into each ceiling by a test with a small fixture, and the
/// incompleteness it stamps can be asserted.
/// Are these bytes plain text?
///
/// Login accounting is a C struct array: fixed-width fields, embedded NULs,
/// binary timestamps. A window that is entirely printable ASCII (plus the
/// ordinary whitespace) is a configuration file, a script or a note — not a
/// truncated log. Empty input is not text; the caller handles that case
/// separately and more loudly.
fn looks_like_text(window: &[u8]) -> bool {
    if window.is_empty() {
        return false;
    }
    window
        .iter()
        .all(|b| matches!(b, 0x09 | 0x0a | 0x0d | 0x20..=0x7e))
}

pub(crate) fn parse_with_limits(artifact: &Artifact, limits: Limits) -> Vec<Artifact> {
    let name = meta_str(artifact, &["name", "file_name"]);
    let path = meta_str(artifact, &["path", "source_path", "full_path"]);
    let hint = role_hint(&name, &path);
    let display_name = if name.is_empty() {
        basename(&path).to_string()
    } else {
        name.clone()
    };

    let Some(data) = artifact.data.as_ref() else {
        // A file named `wtmp` whose content we never received is not the same
        // as a `wtmp` with no logins in it, and must not be silently dropped.
        if hint == RoleHint::Unknown {
            return Vec::new();
        }
        return vec![undetected_status(
            artifact,
            &display_name,
            hint,
            DetectFailure::Unreadable,
            0,
        )];
    };
    let ds: &dyn DataSource = data.as_ref();
    let declared = ds.size();

    let window = read_capped(ds, DETECT_BYTES);
    match detect(&window, declared, hint) {
        Detected::Utmp(detection) => {
            parse_utmp(artifact, ds, &display_name, declared, detection, limits)
        }
        Detected::Lastlog(detection) => {
            parse_lastlog(artifact, ds, &display_name, declared, detection)
        }
        Detected::NotRecognized(failure) => {
            // A file whose bytes are plain text was never login accounting,
            // whatever it is called. `/etc/logrotate.d/wtmp` and
            // `/etc/logrotate.d/btmp` are logrotate CONFIGURATION — four lines
            // of text each — and filing "login accounting could not be read"
            // about them put two false findings on the screen an examiner reads
            // to answer "who logged in" (UI-030, the HUNT-084 shape).
            //
            // An EMPTY file keeps its record: a zeroed `wtmp` is a classic
            // anti-forensic artefact, and it has no bytes to be text.
            if failure != DetectFailure::Empty && looks_like_text(&window) {
                debug!(
                    artifact = %artifact.id,
                    file = %display_name,
                    "named as login accounting but holds text; not claimed"
                );
                return Vec::new();
            }
            if hint == RoleHint::Unknown {
                debug!(
                    artifact = %artifact.id,
                    reason = failure.tag(),
                    "not a login-accounting file"
                );
                Vec::new()
            } else {
                warn!(
                    artifact = %artifact.id,
                    file = %display_name,
                    reason = failure.tag(),
                    "file is named as login accounting but was not recognised"
                );
                vec![undetected_status(
                    artifact,
                    &display_name,
                    hint,
                    failure,
                    declared,
                )]
            }
        }
    }
}

// --- provenance shared by every emitted artifact -----------------------------

/// The parse-wide facts every emitted artifact carries, so a record can always
/// be traced back to the file, the layout and the byte order that produced it.
struct Provenance {
    case_id: Uuid,
    parent: Uuid,
    file_name: String,
    source_file: &'static str,
    role_from_filename: bool,
    layout: &'static str,
    /// Which `ut_type` enumeration the layout's type field was read against.
    /// Recorded on every artifact because the names in `ut_type` are only
    /// meaningful against it, and `None` for `lastlog`, which has no type
    /// field to read.
    type_dialect: Option<&'static str>,
    endian: &'static str,
    /// Set when our own read was cut short, so downstream never presents a
    /// prefix of the evidence as the whole of it.
    incomplete: Option<&'static str>,
    /// Set when the *file* ends mid-record — the signature of a truncated or
    /// tampered-with log.
    file_truncated: bool,
}

impl Provenance {
    fn base(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("source_file".into(), json!(self.source_file));
        m.insert("source_file_name".into(), json!(self.file_name));
        m.insert(
            "source_role_from_filename".into(),
            json!(self.role_from_filename),
        );
        m.insert("record_layout".into(), json!(self.layout));
        if let Some(dialect) = self.type_dialect {
            m.insert("record_type_dialect".into(), json!(dialect));
        }
        m.insert("byte_order".into(), json!(self.endian));
        if let Some(reason) = self.incomplete {
            m.insert("content_incomplete".into(), json!(true));
            m.insert("content_incomplete_reason".into(), json!(reason));
        }
        if self.file_truncated {
            m.insert("source_file_truncated".into(), json!(true));
        }
        m
    }

    fn record(&self, map: Map<String, Value>) -> Artifact {
        Artifact::new(
            self.case_id,
            ArtifactType::ParsedRecord,
            None,
            Value::Object(map),
        )
        .with_parent(self.parent)
    }

    /// Build one timeline row. `timestamp` is a bare i64 of UTC Unix seconds —
    /// the source is genuinely UTC, so no `timezone` tag is set (that tag is
    /// for wall-clock-local formats such as FAT and shellbags).
    fn timeline(
        &self,
        timestamp: i64,
        timestamp_desc: &str,
        short_desc: String,
        details: Map<String, Value>,
    ) -> Artifact {
        let mut m = self.base();
        m.insert("timestamp".into(), json!(timestamp));
        m.insert("timestamp_desc".into(), json!(timestamp_desc));
        m.insert("source_module".into(), json!(MODULE_ID));
        m.insert("short_desc".into(), json!(short_desc));
        for (k, v) in details.iter() {
            m.insert(k.clone(), v.clone());
        }
        // `full_details` must itself be valid JSON: the timeline table exposes a
        // generated column over it.
        let full = Value::Object(details).to_string();
        m.insert("full_details".into(), json!(full));
        Artifact::new(
            self.case_id,
            ArtifactType::TimelineEvent,
            None,
            Value::Object(m),
        )
        .with_parent(self.parent)
    }
}

// --- utmp / wtmp / btmp ------------------------------------------------------

/// The safety ceilings one `struct utmp` parse runs under.
///
/// They are a parameter rather than constants read inline so that a test can
/// drive the *production* code path into each cap with a small fixture. A cap
/// exercised only in theory is a cap whose incompleteness reporting has never
/// been checked, which is how a truncated result comes to be presented as a
/// complete one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Ceiling on records decoded from the file.
    max_records: usize,
    /// Ceiling on reconstructed sessions.
    max_sessions: usize,
}

impl Limits {
    /// The ceilings used on real evidence.
    pub(crate) fn production() -> Self {
        Self {
            max_records: MAX_UTMP_RECORDS,
            max_sessions: MAX_SESSIONS,
        }
    }

    /// Ceilings low enough for a test fixture to reach them.
    #[cfg(test)]
    pub(crate) fn testing(max_records: usize, max_sessions: usize) -> Self {
        Self {
            max_records,
            max_sessions,
        }
    }
}

fn parse_utmp(
    artifact: &Artifact,
    ds: &dyn DataSource,
    display_name: &str,
    declared: u64,
    detection: UtmpDetection,
    limits: Limits,
) -> Vec<Artifact> {
    let buf = read_capped(ds, MAX_UTMP_BYTES);
    let bytes_read = buf.len() as u64;
    let expected = declared.min(MAX_UTMP_BYTES);
    let incomplete = if declared > MAX_UTMP_BYTES {
        Some(IncompleteReason::CapReached.as_str())
    } else if bytes_read < expected {
        Some(IncompleteReason::ShortRead.as_str())
    } else {
        None
    };

    let record_size = detection.layout.record_size;
    let mut records: Vec<UtmpRecord> = Vec::new();
    let mut empty_records = 0usize;
    let mut anomalous_records = 0usize;
    let mut record_cap_reached = false;
    let mut offset = 0usize;
    let mut index = 0usize;
    while let Some(end) = offset.checked_add(record_size) {
        if end > buf.len() {
            break;
        }
        if records.len() >= limits.max_records {
            record_cap_reached = true;
            break;
        }
        match decode_utmp(&buf, offset, index, detection.layout, detection.endian) {
            Ok(rec) => {
                if rec.fault.is_some() {
                    anomalous_records = anomalous_records.saturating_add(1);
                }
                records.push(rec);
            }
            Err(record::RecordReject::Empty) => empty_records = empty_records.saturating_add(1),
            Err(_) => break,
        }
        offset = end;
        index = index.saturating_add(1);
    }
    // Bytes left over inside what we read: the file ends mid-record.
    let leftover = if record_cap_reached {
        0
    } else {
        bytes_read.saturating_sub(offset as u64)
    };
    let file_truncated =
        detection.trailing_partial_bytes > 0 || (leftover > 0 && incomplete.is_none());

    let is_btmp = detection.role == UtmpRole::Btmp;
    // Reconstruction happens BEFORE the provenance block is built, because the
    // session cap is a cap: if it bites, every artifact produced from this file
    // has to carry `content_incomplete`, not just the status row. A truncated
    // session inventory that reads as complete tells an examiner that an
    // account's later sessions do not exist.
    //
    // btmp holds attempts that were rejected. Pairing them into sessions would
    // assert that a login succeeded, which is exactly what this file records
    // did not happen, so no reconstruction runs for it.
    let built = if is_btmp {
        None
    } else {
        Some(reconstruct(&records, limits.max_sessions))
    };
    let session_cap_reached = built.as_ref().is_some_and(|b| b.session_cap_reached);

    let incomplete = if incomplete.is_none() && (record_cap_reached || session_cap_reached) {
        Some(IncompleteReason::CapReached.as_str())
    } else {
        incomplete
    };

    let prov = Provenance {
        case_id: artifact.case_id,
        parent: artifact.id,
        file_name: display_name.to_string(),
        source_file: detection.role.as_str(),
        role_from_filename: detection.role_from_filename,
        layout: detection.layout.name,
        type_dialect: Some(detection.layout.type_dialect.as_str()),
        endian: detection.endian.as_str(),
        incomplete,
        file_truncated,
    };

    let mut out: Vec<Artifact> = Vec::new();
    let mut sessions_emitted = 0usize;
    let mut failed_emitted = 0usize;
    let mut boots_emitted = 0usize;
    let mut unpaired_logouts = 0usize;
    let mut bookkeeping = 0usize;
    let mut undated_records = 0usize;

    match &built {
        None => {
            for rec in &records {
                let kind = classify(rec);
                match kind {
                    RecordKind::Login => {
                        out.push(failed_login_record(&prov, rec));
                        failed_emitted = failed_emitted.saturating_add(1);
                    }
                    RecordKind::Boot
                    | RecordKind::Shutdown
                    | RecordKind::Runlevel
                    | RecordKind::ClockSetNew
                    | RecordKind::ClockSetOld => {
                        // Rare in a btmp, but a dated system event that really is
                        // in the file is evidence and must not be dropped.
                        out.push(boot_event_record(&prov, &boot_event(rec, kind)));
                        boots_emitted = boots_emitted.saturating_add(1);
                    }
                    RecordKind::Logout => unpaired_logouts = unpaired_logouts.saturating_add(1),
                    RecordKind::Bookkeeping | RecordKind::FormatSignature => {
                        bookkeeping = bookkeeping.saturating_add(1)
                    }
                }
            }
        }
        Some(built) => {
            sessions_emitted = built.sessions.len();
            boots_emitted = built.boots.len();
            unpaired_logouts = built.unpaired_logouts;
            bookkeeping = built.bookkeeping;
            for session in &built.sessions {
                out.push(session_record(&prov, session));
            }
            for boot in &built.boots {
                out.push(boot_event_record(&prov, boot));
            }
        }
    }

    // One timeline row per dated record, whatever the role. A record whose
    // stored time is not a plausible date is counted, not dated.
    let mut timeline_emitted = 0usize;
    for rec in &records {
        let kind = classify(rec);
        let Some(desc) = timeline_desc(kind, rec.dialect, is_btmp) else {
            continue;
        };
        let Some(ts) = rec.tv_sec else {
            undated_records = undated_records.saturating_add(1);
            continue;
        };
        out.push(prov.timeline(
            ts,
            desc,
            timeline_short_desc(kind, rec, is_btmp),
            record_details(rec, kind),
        ));
        timeline_emitted = timeline_emitted.saturating_add(1);
    }

    let mut status = prov.base();
    status.insert("type".into(), json!("UtmpParseStatus"));
    status.insert("subtype".into(), json!("utmp_parse_status"));
    status.insert("detected".into(), json!(true));
    status.insert("declared_size".into(), json!(declared));
    status.insert("bytes_read".into(), json!(bytes_read));
    status.insert("record_size".into(), json!(record_size));
    status.insert("records_decoded".into(), json!(records.len()));
    status.insert("records_empty".into(), json!(empty_records));
    status.insert("records_anomalous".into(), json!(anomalous_records));
    status.insert("records_without_usable_time".into(), json!(undated_records));
    status.insert("sessions".into(), json!(sessions_emitted));
    status.insert("failed_logins".into(), json!(failed_emitted));
    status.insert("boot_events".into(), json!(boots_emitted));
    status.insert("timeline_events".into(), json!(timeline_emitted));
    status.insert("unpaired_logouts".into(), json!(unpaired_logouts));
    status.insert("bookkeeping_records".into(), json!(bookkeeping));
    if let Some(version) = built.as_ref().and_then(|b| b.format_version.as_deref()) {
        // The file's own statement of its format version — the only
        // corroboration of the chosen layout that comes from content rather
        // than from field plausibility.
        status.insert("format_version".into(), json!(version));
    }
    status.insert("detection_valid_sample".into(), json!(detection.valid));
    status.insert("detection_sample_size".into(), json!(detection.sampled));
    status.insert(
        "trailing_partial_bytes".into(),
        json!(detection.trailing_partial_bytes.max(leftover)),
    );
    if record_cap_reached {
        status.insert("record_cap_reached".into(), json!(limits.max_records));
    }
    if session_cap_reached {
        status.insert("session_cap_reached".into(), json!(limits.max_sessions));
    }
    if !detection.role_from_filename {
        status.insert(
            "role_note".into(),
            json!(
                "The file name did not identify this as utmp, wtmp or btmp; its records are \
                 reported as session history. Failed-login semantics are never inferred from \
                 content."
            ),
        );
    }
    status.insert(
        "name".into(),
        json!(format!("Login accounting parsed: {display_name}")),
    );
    status.insert(
        "short_desc".into(),
        json!(format!(
            "{display_name}: {} records, {} sessions, {} failed logins ({}, {})",
            records.len(),
            sessions_emitted,
            failed_emitted,
            detection.layout.name,
            detection.endian.as_str()
        )),
    );
    out.push(prov.record(status));
    out
}

fn session_record(prov: &Provenance, session: &LoginSession) -> Artifact {
    let mut m = prov.base();
    m.insert("type".into(), json!("LoginSession"));
    m.insert("subtype".into(), json!("utmp_session"));
    m.insert("user".into(), json!(session.user));
    m.insert("tty".into(), json!(session.line));
    if !session.host.is_empty() {
        m.insert("host".into(), json!(session.host));
    }
    if let Some(addr) = session.addr {
        m.insert("ip".into(), json!(addr.to_string()));
    }
    m.insert("pid".into(), json!(session.pid));
    m.insert("session_id".into(), json!(session.session));
    m.insert(
        "ut_type".into(),
        json!(record::ut_type_name(session.dialect, session.login_ut_type)),
    );
    m.insert("ut_type_raw".into(), json!(session.login_ut_type));
    m.insert("ut_id".into(), json!(session.id));
    m.insert("record_index".into(), json!(session.login_index));
    match session.start {
        Some(start) => {
            m.insert("login_time".into(), json!(start));
            m.insert("date".into(), json!(start));
            if let Some(usec) = session.start_usec {
                m.insert("login_time_usec".into(), json!(usec));
            }
        }
        None => {
            // The record exists; its clock value does not survive the
            // plausibility check. Say so, and show the raw value.
            m.insert("login_time_unusable".into(), json!(true));
            m.insert("login_time_raw".into(), json!(session.start_raw));
        }
    }
    if let Some(end) = session.end {
        m.insert("logout_time".into(), json!(end));
    }
    if let Some(duration) = session.duration {
        m.insert("duration_seconds".into(), json!(duration));
    }
    if let Some(bound) = session.bounded_before {
        // Not a logout: the time of the boot/shutdown that the session did not
        // survive. Named separately so it can never be read as one.
        m.insert("bounded_before_time".into(), json!(bound));
    }
    if let Some(max) = session.max_duration {
        m.insert("max_duration_seconds".into(), json!(max));
    }
    m.insert("status".into(), json!(session.status.as_str()));
    m.insert("closed_by".into(), json!(session.closed_by.as_str()));
    let source = session.source();
    m.insert(
        "name".into(),
        json!(match &source {
            Some(s) => format!("{} @ {} ({})", session.user, session.line, s),
            None => format!("{} @ {}", session.user, session.line),
        }),
    );
    m.insert("short_desc".into(), json!(session_short_desc(session)));
    prov.record(m)
}

fn session_short_desc(session: &LoginSession) -> String {
    let from = match session.source() {
        Some(s) => format!(" from {s}"),
        None => String::new(),
    };
    let when = match (session.status, session.duration) {
        (SessionStatus::LoggedOut, Some(d)) => format!(" ({})", humanize_duration(d)),
        (SessionStatus::StillLoggedIn, _) => " (still logged in)".to_string(),
        (SessionStatus::GoneNoLogout, _) => " (gone - no logout)".to_string(),
        _ => String::new(),
    };
    format!(
        "Login session: {}{} on {}{}",
        session.user, from, session.line, when
    )
}

fn failed_login_record(prov: &Provenance, rec: &UtmpRecord) -> Artifact {
    let mut m = prov.base();
    m.insert("type".into(), json!("FailedLogin"));
    m.insert("subtype".into(), json!("btmp_failed_login"));
    m.insert("user".into(), json!(rec.user));
    m.insert("tty".into(), json!(rec.line));
    if !rec.host.is_empty() {
        m.insert("host".into(), json!(rec.host));
    }
    if let Some(addr) = rec.addr {
        m.insert("ip".into(), json!(addr.to_string()));
    }
    m.insert("pid".into(), json!(rec.pid));
    m.insert(
        "ut_type".into(),
        json!(record::ut_type_name(rec.dialect, rec.ut_type)),
    );
    m.insert("ut_type_raw".into(), json!(rec.ut_type));
    m.insert("record_index".into(), json!(rec.index));
    match rec.tv_sec {
        Some(ts) => {
            m.insert("time".into(), json!(ts));
            m.insert("date".into(), json!(ts));
            if let Some(usec) = rec.tv_usec {
                m.insert("time_usec".into(), json!(usec));
            }
        }
        None => {
            m.insert("time_unusable".into(), json!(true));
            m.insert("time_raw".into(), json!(rec.tv_sec_raw));
        }
    }
    if let Some(fault) = rec.fault {
        m.insert("record_anomaly".into(), json!(fault.tag()));
        m.insert("record_anomaly_detail".into(), json!(fault.to_string()));
    }
    let source = source_of(rec);
    m.insert(
        "name".into(),
        json!(match &source {
            Some(s) => format!("{} <- {} (failed)", rec.user, s),
            None => format!("{} (failed)", rec.user),
        }),
    );
    m.insert("short_desc".into(), json!(failed_short_desc(rec)));
    prov.record(m)
}

fn failed_short_desc(rec: &UtmpRecord) -> String {
    match source_of(rec) {
        Some(s) => format!("Failed login: {} from {}", rec.user, s),
        None => format!("Failed login: {} on {}", rec.user, rec.line),
    }
}

fn boot_event_record(prov: &Provenance, boot: &BootEvent) -> Artifact {
    let mut m = prov.base();
    m.insert("type".into(), json!("BootEvent"));
    m.insert("subtype".into(), json!("utmp_boot"));
    m.insert("kind".into(), json!(boot.kind.as_str()));
    m.insert("ut_type".into(), json!(boot.ut_type_name()));
    m.insert("ut_type_raw".into(), json!(boot.ut_type));
    m.insert("record_index".into(), json!(boot.index));
    match boot.time {
        Some(ts) => {
            m.insert("time".into(), json!(ts));
            m.insert("date".into(), json!(ts));
        }
        None => {
            m.insert("time_unusable".into(), json!(true));
        }
    }
    if let Some(kernel) = &boot.kernel {
        m.insert("kernel".into(), json!(kernel));
    }
    if let Some(level) = boot.runlevel {
        m.insert("runlevel".into(), json!(level.to_string()));
    }
    if let Some(level) = boot.previous_runlevel {
        m.insert("previous_runlevel".into(), json!(level.to_string()));
    }
    m.insert("name".into(), json!(boot_name(boot)));
    m.insert("short_desc".into(), json!(boot_short_desc(boot)));
    prov.record(m)
}

fn boot_name(boot: &BootEvent) -> String {
    match boot.kind {
        RecordKind::Boot => "System boot".to_string(),
        RecordKind::Shutdown => "System shutdown".to_string(),
        RecordKind::Runlevel => match boot.runlevel {
            Some(level) => format!("Run-level change to {level}"),
            None => "Run-level change".to_string(),
        },
        RecordKind::ClockSetNew => "Clock change (new time)".to_string(),
        RecordKind::ClockSetOld => "Clock change (old time)".to_string(),
        _ => "System event".to_string(),
    }
}

fn boot_short_desc(boot: &BootEvent) -> String {
    let name = boot_name(boot);
    match (&boot.kernel, boot.kind) {
        (Some(kernel), RecordKind::Boot) => format!("{name}: {kernel}"),
        _ => name,
    }
}

/// Source of a record: hostname when recorded, else the numeric address, else
/// nothing at all (a local console login has neither).
fn source_of(rec: &UtmpRecord) -> Option<String> {
    if !rec.host.is_empty() {
        Some(rec.host.clone())
    } else {
        rec.addr.map(|a| a.to_string())
    }
}

fn timeline_short_desc(kind: RecordKind, rec: &UtmpRecord, is_btmp: bool) -> String {
    if is_btmp && kind == RecordKind::Login {
        return failed_short_desc(rec);
    }
    match kind {
        RecordKind::Login => match source_of(rec) {
            Some(s) => format!("Login: {} from {} on {}", rec.user, s, rec.line),
            None => format!("Login: {} on {}", rec.user, rec.line),
        },
        RecordKind::Logout => format!("Logout: {}", rec.line),
        RecordKind::Boot => {
            if rec.host.is_empty() {
                "System boot".to_string()
            } else {
                format!("System boot: {}", rec.host)
            }
        }
        RecordKind::Shutdown => "System shutdown".to_string(),
        RecordKind::Runlevel => match sessions::runlevel_of(rec) {
            Some(level) => format!("Run-level change to {level}"),
            None => "Run-level change".to_string(),
        },
        RecordKind::ClockSetNew => "System clock changed (new time)".to_string(),
        RecordKind::ClockSetOld => "System clock changed (old time)".to_string(),
        RecordKind::Bookkeeping => "Login-accounting bookkeeping record".to_string(),
        RecordKind::FormatSignature => {
            if rec.user.is_empty() {
                "Login-accounting format signature".to_string()
            } else {
                format!("Login-accounting format signature: {}", rec.user)
            }
        }
    }
}

/// The per-record detail object stored as `full_details` on a timeline row.
fn record_details(rec: &UtmpRecord, kind: RecordKind) -> Map<String, Value> {
    let mut d = Map::new();
    d.insert("user".into(), json!(rec.user));
    d.insert("tty".into(), json!(rec.line));
    d.insert("ut_id".into(), json!(rec.id));
    if !rec.host.is_empty() {
        d.insert("host".into(), json!(rec.host));
    }
    if let Some(addr) = rec.addr {
        d.insert("ip".into(), json!(addr.to_string()));
    }
    d.insert("pid".into(), json!(rec.pid));
    d.insert("session_id".into(), json!(rec.session));
    d.insert(
        "ut_type".into(),
        json!(record::ut_type_name(rec.dialect, rec.ut_type)),
    );
    d.insert("ut_type_raw".into(), json!(rec.ut_type));
    d.insert("event".into(), json!(kind.as_str()));
    d.insert("record_index".into(), json!(rec.index));
    if let Some(usec) = rec.tv_usec {
        // Sub-second precision lives here: the indexed timestamp column is
        // whole seconds by contract.
        d.insert("tv_usec".into(), json!(usec));
    }
    if let Some(fault) = rec.fault {
        d.insert("record_anomaly".into(), json!(fault.tag()));
    }
    d
}

// --- lastlog -----------------------------------------------------------------

fn parse_lastlog(
    artifact: &Artifact,
    ds: &dyn DataSource,
    display_name: &str,
    declared: u64,
    detection: LastlogDetection,
) -> Vec<Artifact> {
    let layout = detection.layout;
    let record_size = layout.record_size as u64;
    let total_records = declared / record_size;
    let walk_records = total_records.min(MAX_LASTLOG_RECORDS);
    let uid_cap_reached = total_records > MAX_LASTLOG_RECORDS;

    let mut emitted_records = 0usize;
    let mut nonzero = 0usize;
    let mut anomalous = 0usize;
    let mut undated = 0usize;
    let mut emit_cap_reached = false;
    let mut short_read = false;
    let mut out: Vec<Artifact> = Vec::new();

    let mut prov = Provenance {
        case_id: artifact.case_id,
        parent: artifact.id,
        file_name: display_name.to_string(),
        source_file: "lastlog",
        role_from_filename: true,
        layout: layout.name,
        // `struct lastlog` has no `ut_type`, so there is no enumeration to
        // name. Absent rather than guessed at.
        type_dialect: None,
        endian: detection.endian.as_str(),
        incomplete: None,
        file_truncated: !declared.is_multiple_of(record_size),
    };

    // Streamed in blocks: a sparse lastlog can be gigabytes of holes, and
    // buffering it would put the worker at the mercy of the file's max UID.
    let block_bytes = (LASTLOG_BLOCK_RECORDS.saturating_mul(record_size)) as usize;
    let mut block = vec![0u8; block_bytes];
    let mut first_uid = 0u64;
    while first_uid < walk_records {
        let count = LASTLOG_BLOCK_RECORDS.min(walk_records.saturating_sub(first_uid));
        let want = (count.saturating_mul(record_size)) as usize;
        let Some(offset) = first_uid.checked_mul(record_size) else {
            short_read = true;
            break;
        };
        // `want` cannot exceed the block by construction; slice fallibly anyway
        // so a future change to the block sizing cannot turn into a panic in a
        // worker thread.
        let Some(window) = block.get_mut(..want) else {
            short_read = true;
            break;
        };
        let got = read_full(ds, offset, window);
        if got < want {
            short_read = true;
        }
        let usable = got / layout.record_size;
        for i in 0..usable {
            let Some(start) = i.checked_mul(layout.record_size) else {
                break;
            };
            let Some(end) = start.checked_add(layout.record_size) else {
                break;
            };
            let Some(bytes) = block.get(start..end) else {
                break;
            };
            let Ok(uid) = u32::try_from(first_uid.saturating_add(i as u64)) else {
                break;
            };
            let rec = match decode_lastlog(bytes, uid, layout, detection.endian) {
                Ok(rec) => rec,
                // An all-zero record means that UID has never logged in. Emitting
                // a row for it would invent an event; `lastlog(8)` prints
                // "Never logged in" for exactly these.
                Err(_) => continue,
            };
            nonzero = nonzero.saturating_add(1);
            if rec.fault.is_some() {
                anomalous = anomalous.saturating_add(1);
            }
            if emitted_records >= MAX_LASTLOG_EMIT {
                emit_cap_reached = true;
                break;
            }
            out.push(last_login_record(&prov, &rec));
            emitted_records = emitted_records.saturating_add(1);
            match rec.ll_time {
                Some(ts) => {
                    let mut details = Map::new();
                    details.insert("uid".into(), json!(rec.uid));
                    details.insert("tty".into(), json!(rec.line));
                    if !rec.host.is_empty() {
                        details.insert("host".into(), json!(rec.host));
                    }
                    if let Some(addr) = rec.addr {
                        details.insert("ip".into(), json!(addr.to_string()));
                    }
                    details.insert("event".into(), json!("last_login"));
                    out.push(prov.timeline(
                        ts,
                        "Last login (lastlog)",
                        last_login_short_desc(&rec),
                        details,
                    ));
                }
                None => undated = undated.saturating_add(1),
            }
        }
        if emit_cap_reached || usable < count as usize {
            break;
        }
        first_uid = first_uid.saturating_add(count);
    }

    let incomplete = if uid_cap_reached || emit_cap_reached {
        Some(IncompleteReason::CapReached.as_str())
    } else if short_read {
        Some(IncompleteReason::ShortRead.as_str())
    } else {
        None
    };
    if incomplete.is_some() {
        // Restamp every already-built artifact: a truncated inventory that
        // looks complete is the failure this flag exists to prevent.
        prov.incomplete = incomplete;
        for produced in out.iter_mut() {
            if let Some(obj) = produced.metadata.as_object_mut() {
                obj.insert("content_incomplete".into(), json!(true));
                obj.insert(
                    "content_incomplete_reason".into(),
                    json!(incomplete.unwrap_or(IncompleteReason::CapReached.as_str())),
                );
            }
        }
    }

    let mut status = prov.base();
    status.insert("type".into(), json!("UtmpParseStatus"));
    status.insert("subtype".into(), json!("lastlog_parse_status"));
    status.insert("detected".into(), json!(true));
    status.insert("declared_size".into(), json!(declared));
    status.insert("record_size".into(), json!(layout.record_size));
    status.insert("uid_slots_total".into(), json!(total_records));
    status.insert("uid_slots_walked".into(), json!(walk_records));
    status.insert("records_populated".into(), json!(nonzero));
    status.insert("records_emitted".into(), json!(emitted_records));
    status.insert("records_anomalous".into(), json!(anomalous));
    status.insert("records_without_usable_time".into(), json!(undated));
    status.insert(
        "layout_unconfirmed".into(),
        json!(detection.layout_unconfirmed),
    );
    if detection.layout_unconfirmed {
        status.insert(
            "layout_note".into(),
            json!(
                "No populated record appeared in the detection window, so the record size \
                 follows from the file name and size alone and was not confirmed against data."
            ),
        );
    }
    if uid_cap_reached {
        status.insert("uid_cap_reached".into(), json!(MAX_LASTLOG_RECORDS));
    }
    if emit_cap_reached {
        status.insert("emit_cap_reached".into(), json!(MAX_LASTLOG_EMIT));
    }
    status.insert(
        "name".into(),
        json!(format!("lastlog parsed: {display_name}")),
    );
    status.insert(
        "short_desc".into(),
        json!(format!(
            "{display_name}: {emitted_records} accounts with a recorded last login out of \
             {walk_records} UID slots examined"
        )),
    );
    out.push(prov.record(status));
    out
}

fn last_login_record(prov: &Provenance, rec: &LastlogRecord) -> Artifact {
    let mut m = prov.base();
    m.insert("type".into(), json!("LastLogin"));
    m.insert("subtype".into(), json!("lastlog"));
    m.insert("uid".into(), json!(rec.uid));
    // lastlog stores no username. Resolving the UID needs /etc/passwd, which
    // this parser does not read; a guess here would put a name on the wrong
    // account.
    m.insert("user".into(), Value::Null);
    m.insert("tty".into(), json!(rec.line));
    if !rec.host.is_empty() {
        m.insert("host".into(), json!(rec.host));
    }
    if let Some(addr) = rec.addr {
        m.insert("ip".into(), json!(addr.to_string()));
    }
    match rec.ll_time {
        Some(ts) => {
            m.insert("last_login_time".into(), json!(ts));
            m.insert("date".into(), json!(ts));
        }
        None => {
            m.insert("last_login_time_unusable".into(), json!(true));
            m.insert("last_login_time_raw".into(), json!(rec.ll_time_raw));
        }
    }
    if let Some(fault) = rec.fault {
        m.insert("record_anomaly".into(), json!(fault.tag()));
        m.insert("record_anomaly_detail".into(), json!(fault.to_string()));
    }
    m.insert("name".into(), json!(format!("uid {} last login", rec.uid)));
    m.insert("short_desc".into(), json!(last_login_short_desc(rec)));
    prov.record(m)
}

fn last_login_short_desc(rec: &LastlogRecord) -> String {
    let from = if !rec.host.is_empty() {
        format!(" from {}", rec.host)
    } else {
        String::new()
    };
    format!("Last login uid {}{} on {}", rec.uid, from, rec.line)
}

// --- refusals ----------------------------------------------------------------

/// A record stating that a file whose *name* claims it is login accounting was
/// not parsed, and why.
///
/// This exists because the alternative — returning nothing — is
/// indistinguishable from "this `wtmp` recorded no logins". A zeroed or
/// truncated `wtmp`/`btmp` is a classic anti-forensic move, and it has to show
/// up in the case rather than as silence.
fn undetected_status(
    artifact: &Artifact,
    display_name: &str,
    hint: RoleHint,
    failure: DetectFailure,
    declared: u64,
) -> Artifact {
    let claimed = match hint {
        RoleHint::Utmp => "utmp",
        RoleHint::Wtmp => "wtmp",
        RoleHint::Btmp => "btmp",
        RoleHint::Lastlog => "lastlog",
        RoleHint::Unknown => "unknown",
    };
    let mut m = Map::new();
    m.insert("type".into(), json!("UtmpParseStatus"));
    m.insert("subtype".into(), json!("utmp_not_parsed"));
    m.insert("detected".into(), json!(false));
    m.insert("source_file".into(), json!(claimed));
    m.insert("source_file_name".into(), json!(display_name));
    m.insert("source_role_from_filename".into(), json!(true));
    m.insert("declared_size".into(), json!(declared));
    m.insert("failure_reason".into(), json!(failure.tag()));
    m.insert("failure_detail".into(), json!(failure.to_string()));
    m.insert(
        "message".into(),
        json!(
            "This file is named as login accounting but its contents could not be confirmed \
             as any known record layout — glibc utmp, musl utmpx or Darwin utmpx — so nothing \
             was parsed from it. Absence of login records here is NOT evidence that no logins \
             occurred."
        ),
    );
    m.insert(
        "name".into(),
        json!(format!("Login accounting not parsed: {display_name}")),
    );
    m.insert(
        "short_desc".into(),
        json!(format!(
            "{display_name} ({claimed}) was not parsed: {}",
            failure
        )),
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(m),
    )
    .with_parent(artifact.id)
}

// --- small helpers -----------------------------------------------------------

fn meta_str(artifact: &Artifact, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = artifact.metadata.get(*key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    String::new()
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
