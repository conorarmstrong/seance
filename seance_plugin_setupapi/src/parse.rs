//! The setupapi device-install log's grammar, as measured.
//!
//! `ROADMAP` §2.6. Windows writes `%WINDIR%\INF\setupapi.dev.log` (and
//! `setupapi.setup.log`, and one `setupapi.offline*.log` per offline servicing
//! pass) as it installs devices. It is the **second, independent** source for
//! when a device was first connected: the registry's device-property keys are
//! the first, and two sources agreeing is worth more than either alone.
//!
//! # The grammar
//!
//! Plain ASCII. Eight-line preamble: `[Device Install Log]`, five
//! five-space-indented `Key = Value` lines, an empty line, `[BeginLog]`. Then
//! `[Boot Session: YYYY/MM/DD HH:MM:SS.mmm]` lines and sections:
//!
//! ```text
//! >>>  [Device Install (Hardware initiated) - HID\DELLABCE\3&14ed0212&0&0000]
//! >>>  Section start 2018/03/27 05:22:22.016
//!      dvi: {Build Driver List} 05:22:22.033
//! <<<  Section end 2018/03/27 05:22:22.475
//! <<<  [Exit status: SUCCESS]
//! ```
//!
//! # What this parser is written against
//!
//! Every item below is real, in one of the three logs measured for this file,
//! and each is a thing a straightforward parser loses without saying so. See
//! `tests.rs` for the measurements and the test that pins each.
//!
//! * Boot-session times are **not** in chronological order, and a section can
//!   start hours **before** the boot session it sits under. File order is kept
//!   and the disagreement is stated; nothing is sorted, clamped or dropped.
//! * A section can have **no body line**.
//! * A body line may begin `!` or `!!!` in column 0 rather than with
//!   indentation, and `cmd:` is indented six spaces where every other tag is
//!   indented five.
//! * The header subject is **absent on most sections**, and where present may
//!   be an INF path, a bare GUID, a two-segment hardware id or a full device
//!   instance id — so it is shape-classified before anything reads it as a
//!   device.
//! * The full instance id is sometimes only on an `ndv:` body line.
//!
//! # And the times are local, with no offset recorded anywhere
//!
//! Checked across all three files for `UTC`, `GMT`, `timezone`, `Bias`,
//! `daylight`, `DST` and the literal `+HH:MM` / `+HHMM` shapes: every count is
//! zero. So a time here is local to a machine whose offset this file does not
//! state, it is **never** converted, and no timeline event is raised from it —
//! a local time placed on a UTC timeline is wrong by exactly the offset
//! nobody recorded.

use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The line every one of these files opens with.
pub const SELECT_LINE: &[u8] = b"[Device Install Log]";

/// Sections read before the parser stops.
///
/// The largest real log here holds 194. The ceiling is generous and finite: a
/// crafted or corrupt file of repeated header lines would otherwise emit one
/// record per line of a multi-gigabyte file.
pub const MAX_SECTIONS: usize = 200_000;

/// Body lines counted per section before the parser stops counting them. The
/// busiest real section holds a few thousand.
pub const MAX_BODY_LINES: usize = 1_000_000;

/// Whether these bytes are a device-install log.
///
/// **By content, not by name.** All three real files open with the same line,
/// and it does **not** tell the `dev` log from the `setup` log — which is why
/// the file name rides on every record instead of deciding anything here.
pub fn is_device_install_log(bytes: &[u8]) -> bool {
    bytes.starts_with(SELECT_LINE)
}

/// What a section header's ` - <subject>` half is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectKind {
    /// A full device instance id: an enumerator, a hardware id and an instance
    /// — the thing that identifies ONE device on ONE machine.
    DeviceInstanceId,
    /// A two-segment hardware id: a device KIND. Not an instance, and reading
    /// it as one would publish a class of hardware as a connected device.
    HardwareId,
    /// A path to an `.inf`. The commonest non-device subject, and publishing it
    /// as a device is this parser's headline failure mode.
    InfPath,
    /// A bare GUID, as `Sysprep Specialize` carries.
    Guid,
    /// Present and of no shape this build recognises. Reported as stored.
    Unclassified,
}

impl SubjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeviceInstanceId => "device_instance_id",
            Self::HardwareId => "hardware_id",
            Self::InfPath => "inf_path",
            Self::Guid => "guid",
            Self::Unclassified => "unclassified",
        }
    }
}

/// Whether a device-related section records an arrival or a departure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceAction {
    Install,
    Remove,
}

impl DeviceAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Remove => "remove",
        }
    }
}

/// The section kinds whose subject is a device. Anything else — the driver
/// store's own housekeeping, the policy checks, the sysprep passes — is
/// counted in the histogram and is not a device event.
///
/// Matched as a prefix on the kind, because Windows writes both
/// `Device Install (Hardware initiated)` and
/// `Setup online Device Install (Hardware initiated)`.
const DEVICE_INSTALL_KINDS: &[&str] = &[
    "Device Install (",
    "Setup online Device Install (",
    "Device Install(",
];

/// And the one kind that is a removal.
const DEVICE_REMOVE_KINDS: &[&str] = &["Delete Device"];

/// Classify a header subject by its shape.
pub fn classify_subject(subject: &str) -> SubjectKind {
    let s = subject.trim();
    if s.starts_with('{') && s.ends_with('}') && !s.contains('\\') {
        return SubjectKind::Guid;
    }
    let lower = s.to_ascii_lowercase();
    // An INF path: a drive-lettered or UNC path, or anything ending `.inf`.
    // Checked BEFORE the segment count, because an INF path has many
    // backslash-separated segments and would otherwise read as an instance id.
    if lower.ends_with(".inf")
        || s.starts_with("\\\\")
        || (s.len() > 2 && s.as_bytes()[1] == b':' && matches!(s.as_bytes().get(2), Some(b'\\')))
    {
        return SubjectKind::InfPath;
    }
    match s.split('\\').filter(|p| !p.is_empty()).count() {
        // `ENUM\HARDWARE_ID\INSTANCE`.
        n if n >= 3 => SubjectKind::DeviceInstanceId,
        // `PCI\VEN_80EE&DEV_CAFE&…` — a kind, not an instance.
        2 => SubjectKind::HardwareId,
        _ => SubjectKind::Unclassified,
    }
}

/// The device instance id a subject states, or `None` when it states none.
pub fn device_instance_id(subject: &str) -> Option<String> {
    (classify_subject(subject) == SubjectKind::DeviceInstanceId).then(|| subject.trim().to_string())
}

/// One boot session, as written.
#[derive(Clone, Debug)]
pub struct BootSession {
    /// The timestamp exactly as the file holds it. **Local**, no offset.
    pub local_time: String,
    /// 1-based line number, so a claim can be checked against the file.
    pub line: usize,
}

/// One section.
#[derive(Clone, Debug)]
pub struct Section {
    pub kind: String,
    pub subject: Option<String>,
    pub subject_kind: SubjectKind,
    /// The instance id the SUBJECT states, which is not the same thing as an
    /// id found in the body.
    pub instance_id_from_subject: Option<String>,
    /// Instance ids found on `ndv:` body lines, in order of appearance. On
    /// seven real sections this is the only place the instance appears.
    pub body_device_ids: Vec<String>,
    pub start_local: Option<String>,
    pub end_local: Option<String>,
    pub exit_status: Option<String>,
    /// Whether the log closed this section. `false` is what a machine losing
    /// power mid-install leaves behind.
    pub closed: bool,
    pub body_lines: usize,
    /// `!!!`-marked lines, verbatim and trimmed. The only records of a failed
    /// device start in any of the three real logs are two of these.
    pub warnings: Vec<String>,
    /// The `cmd:` line's command — which process drove the install.
    pub command: Option<String>,
    pub device_action: Option<DeviceAction>,
    /// Index into `boot_sessions` of the session this section sits under.
    pub boot_session: Option<usize>,
    pub line: usize,
}

/// A whole log.
#[derive(Clone, Debug, Default)]
pub struct DeviceInstallLog {
    pub header: BTreeMap<String, String>,
    /// The header keys in the order the file gives them.
    pub header_order: Vec<String>,
    pub begin_log_seen: bool,
    pub boot_sessions: Vec<BootSession>,
    pub sections: Vec<Section>,
    pub unclosed_sections: usize,
    /// Times in this file that cannot be read as a monotonic sequence, each
    /// said in words. Real: see the module comment.
    pub clock_anomalies: Vec<String>,
    /// Set when a ceiling stopped the parse. Never silent.
    pub cap_reached: Option<String>,
    pub lines_read: usize,
}

impl DeviceInstallLog {
    /// Every section kind with its count. Nothing is left out: the two
    /// commonest kinds in the largest real log are driver-store housekeeping,
    /// and burying them would be as wrong as hiding them.
    pub fn kind_histogram(&self) -> BTreeMap<String, usize> {
        let mut out: BTreeMap<String, usize> = BTreeMap::new();
        for s in &self.sections {
            *out.entry(s.kind.clone()).or_default() += 1;
        }
        out
    }

    /// Sections that concern a device, which is a minority of them.
    pub fn device_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.device_action.is_some())
    }
}

/// The sentence every time on every record carries.
pub const TIME_BASIS: &str =
    "This time is LOCAL to the machine that wrote the log, and no timezone or offset is recorded \
     anywhere in the file -- checked for UTC, GMT, timezone, Bias, daylight, DST and the literal \
     offset shapes, all of which are absent. It is reported exactly as written and is never \
     converted: converting it would need an offset nobody recorded.";

/// Strip the `>>>` / `<<<` / `!` / `!!!` marker and the indentation.
fn body_payload(line: &str) -> Option<&str> {
    let t = line.trim_end();
    if t.is_empty() {
        return None;
    }
    // A bang marker sits in column 0, where a body line's indentation would
    // otherwise be. 533 lines across the three real logs are of this shape,
    // including the only two failed-device-start records.
    for marker in ["!!!", "!"] {
        if let Some(rest) = t.strip_prefix(marker) {
            return Some(rest.trim());
        }
    }
    // An ordinary body line is indented. `cmd:` is indented six spaces where
    // every other tag is indented five, so this accepts any indentation rather
    // than a fixed width.
    (t.starts_with(' ')).then(|| t.trim())
}

/// The `ENUM\HW\INSTANCE`-shaped ids inside a body line's text.
fn instance_ids_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // `ndv:` is the only prefix that states a device-install intent in a
    // machine-readable brace form: `{Installing device - <id>}`,
    // `{Update Device Driver - <id>}`.
    let Some(rest) = text.strip_prefix("ndv:") else {
        return out;
    };
    let rest = rest.trim();
    if let Some(inner) = rest.strip_prefix('{').and_then(|s| s.split('}').next()) {
        if let Some((_, id)) = inner.rsplit_once(" - ") {
            let id = id.trim();
            if classify_subject(id) == SubjectKind::DeviceInstanceId {
                out.push(id.to_string());
            }
        }
    }
    out
}

/// Parse a whole log.
pub fn parse(text: &str) -> DeviceInstallLog {
    let mut out = DeviceInstallLog::default();
    let mut current: Option<Section> = None;
    let mut in_preamble = true;

    for (i, raw) in text.split('\n').enumerate() {
        let line_no = i + 1;
        out.lines_read = line_no;
        // Split on LF and trim a trailing CR, so a CRLF file and an LF file
        // parse identically and no stray CR lands inside a timestamp.
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();

        if in_preamble {
            if trimmed == "[BeginLog]" {
                out.begin_log_seen = true;
                in_preamble = false;
                continue;
            }
            if trimmed.is_empty() || trimmed == "[Device Install Log]" {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once(" = ") {
                let key = k.trim().to_string();
                if !out.header.contains_key(&key) {
                    out.header_order.push(key.clone());
                }
                out.header.insert(key, v.trim().to_string());
                continue;
            }
            // Anything else ends the preamble without a `[BeginLog]`.
            in_preamble = false;
        }

        if let Some(rest) = trimmed
            .strip_prefix("[Boot Session:")
            .and_then(|s| s.strip_suffix(']'))
        {
            let local_time = rest.trim().to_string();
            if let Some(prev) = out.boot_sessions.last() {
                if local_time < prev.local_time {
                    out.clock_anomalies.push(format!(
                        "The boot session at line {line_no} is {local_time}, which is earlier \
                         than the one before it at line {} ({}). Sessions are reported in FILE \
                         ORDER and are never sorted: the file's order is the order the machine \
                         wrote them, and a clock that moved is a fact about the machine rather \
                         than a reason to reorder its log.",
                        prev.line, prev.local_time
                    ));
                }
            }
            out.boot_sessions.push(BootSession {
                local_time,
                line: line_no,
            });
            continue;
        }

        // A section header.
        if let Some(rest) = line.strip_prefix(">>>") {
            let rest = rest.trim();
            if let Some(inner) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                if let Some(sec) = current.take() {
                    push_section(&mut out, sec);
                }
                if out.sections.len() >= MAX_SECTIONS {
                    if out.cap_reached.is_none() {
                        out.cap_reached = Some(format!(
                            "The section ceiling of {MAX_SECTIONS} was reached at line \
                             {line_no}. The sections below this point were not read, so this \
                             log holds MORE device activity than is reported here -- the \
                             largest real log measured for this parser holds 194."
                        ));
                    }
                    break;
                }
                let (kind, subject) = match inner.split_once(" - ") {
                    Some((k, s)) => (k.trim().to_string(), Some(s.trim().to_string())),
                    None => (inner.trim().to_string(), None),
                };
                let subject_kind = subject
                    .as_deref()
                    .map(classify_subject)
                    .unwrap_or(SubjectKind::Unclassified);
                let instance_id_from_subject = subject.as_deref().and_then(device_instance_id);
                let device_action = if DEVICE_REMOVE_KINDS.iter().any(|k| kind.starts_with(k)) {
                    Some(DeviceAction::Remove)
                } else if DEVICE_INSTALL_KINDS.iter().any(|k| kind.starts_with(k)) {
                    Some(DeviceAction::Install)
                } else {
                    None
                };
                current = Some(Section {
                    kind,
                    subject,
                    subject_kind,
                    instance_id_from_subject,
                    body_device_ids: Vec::new(),
                    start_local: None,
                    end_local: None,
                    exit_status: None,
                    closed: false,
                    body_lines: 0,
                    warnings: Vec::new(),
                    command: None,
                    device_action,
                    boot_session: out.boot_sessions.len().checked_sub(1),
                    line: line_no,
                });
                continue;
            }
            if let Some(start) = rest.strip_prefix("Section start ") {
                if let Some(sec) = current.as_mut() {
                    sec.start_local = Some(start.trim().to_string());
                }
                continue;
            }
            continue;
        }

        // A section footer.
        if let Some(rest) = line.strip_prefix("<<<") {
            let rest = rest.trim();
            if let Some(end) = rest.strip_prefix("Section end ") {
                if let Some(sec) = current.as_mut() {
                    sec.end_local = Some(end.trim().to_string());
                }
                continue;
            }
            if let Some(status) = rest
                .strip_prefix("[Exit status:")
                .and_then(|s| s.strip_suffix(']'))
            {
                if let Some(mut sec) = current.take() {
                    // Captured as whatever is there. Neither of the two values
                    // the real logs hold is a failure, so this build must not
                    // assume the vocabulary is closed.
                    sec.exit_status = Some(status.trim().to_string());
                    sec.closed = true;
                    push_section(&mut out, sec);
                }
                continue;
            }
            continue;
        }

        // A body line.
        if let Some(payload) = body_payload(line) {
            if let Some(sec) = current.as_mut() {
                if sec.body_lines < MAX_BODY_LINES {
                    sec.body_lines += 1;
                }
                if line.trim_start().starts_with("!!!") || line.starts_with("!!!") {
                    sec.warnings.push(payload.to_string());
                }
                if let Some(cmd) = payload.strip_prefix("cmd:") {
                    let cmd = cmd.trim();
                    if !cmd.is_empty() && sec.command.is_none() {
                        sec.command = Some(cmd.to_string());
                    }
                }
                for id in instance_ids_in(payload) {
                    if !sec.body_device_ids.contains(&id) {
                        sec.body_device_ids.push(id);
                    }
                }
            }
        }
    }
    if let Some(sec) = current.take() {
        push_section(&mut out, sec);
    }
    out
}

/// Add a finished section, and state a start time that precedes its own boot
/// session rather than clamping or rejecting it.
fn push_section(out: &mut DeviceInstallLog, sec: Section) {
    if !sec.closed {
        out.unclosed_sections += 1;
    }
    if let (Some(start), Some(bs)) = (
        sec.start_local.as_deref(),
        sec.boot_session.and_then(|i| out.boot_sessions.get(i)),
    ) {
        if start < bs.local_time.as_str() {
            out.clock_anomalies.push(format!(
                "The section at line {} starts at {start}, which is before the boot session it \
                 sits under ({} at line {}). It is reported as written: on real evidence this is \
                 Windows Update replaying an install recorded under an earlier clock, and \
                 clamping or rejecting such a section loses a device install.",
                sec.line, bs.local_time, bs.line
            ));
        }
    }
    out.sections.push(sec);
}

impl Section {
    /// One device-install event as a record.
    pub fn to_json(&self, log_file: &str, log: &DeviceInstallLog) -> Value {
        let name = self
            .instance_id_from_subject
            .clone()
            .or_else(|| self.body_device_ids.first().cloned())
            .or_else(|| self.subject.clone())
            .unwrap_or_else(|| self.kind.clone());
        json!({
            "type": "DeviceInstallEvent",
            "name": name,
            "log_file": log_file,
            // Which installation the log describes. A `setupapi.offline.log`
            // declaring 6.3.9600 inside a 10.0.16299 machine describes the
            // DEPLOYMENT IMAGE's servicing, not this machine's device history,
            // so this rides on every record rather than on the log alone.
            "log_os_version": log.header.get("OS Version"),
            "section_kind": self.kind,
            "section_line": self.line,
            "subject": self.subject,
            "subject_kind": self.subject_kind.as_str(),
            // The id the SUBJECT states, kept apart from ids found in the body:
            // most sections' subjects are not device ids at all.
            "device_instance_id": self.instance_id_from_subject,
            "body_device_instance_ids": self.body_device_ids,
            "device_action": self.device_action.map(|a| a.as_str()),
            "start_local": self.start_local,
            "end_local": self.end_local,
            "exit_status": self.exit_status,
            "section_closed": self.closed,
            "body_lines": self.body_lines,
            "warnings": self.warnings,
            "driven_by_command": self.command,
            "boot_session_local": self
                .boot_session
                .and_then(|i| log.boot_sessions.get(i))
                .map(|b| b.local_time.clone()),
            "time_basis": TIME_BASIS,
            // A local time on a UTC timeline is wrong by exactly the offset
            // nobody recorded, so this record raises no timeline event and
            // says why.
            "timeline_eligible": false,
            "timeline_basis":
                "No timeline event is raised from this record. The timeline is in UTC and this \
                 log records local time with no offset, so placing it would move the event by \
                 the machine's own offset -- which this evidence does not state.",
        })
    }
}
