//! BAM/DAM: the last time each program ran, per user.
//!
//! # What it is
//!
//! Background Activity Moderator, and its desktop sibling DAM, keep a
//! per-SID record of each program's last execution under
//! `ControlSet00N\Services\{bam,dam}\…\UserSettings\<SID>`. Windows 10 1709 and
//! later. It survives the program's deletion and it names the user it ran as,
//! which few artifacts do.
//!
//! `ROADMAP` §2.5.
//!
//! # Two layouts, and both must match
//!
//! Windows 10 1803 writes `Services\bam\UserSettings\<SID>`; 1809 and later
//! insert a `State` segment. A matcher that handled one would report nothing
//! for half the Windows 10 estate — and report it as an absence of executions
//! rather than as a shape it did not look for.
//!
//! # What this module refuses to do
//!
//! **It does not translate `\Device\HarddiskVolumeN` to a drive letter.**
//! `MountedDevices` is in the same hive and §2.6 owns that mapping; until it
//! lands, the NT device name is reported as stored and the record says that it
//! was not resolved. Guessing `HarddiskVolume4` = `C:` would put a drive letter
//! in a report the evidence does not support.
//!
//! **It does not resolve the SID to a user name**, for the same reason: the
//! mapping is elsewhere, and a wrong name is worse than a SID.
//!
//! **It does not classify from the undocumented bytes.** Sixteen bytes follow
//! the FILETIME and only two patterns were ever observed, correlating with the
//! target's shape. The classification comes from the value **name**, which is
//! documented. Reading meaning out of bytes nobody has published would be a
//! guess wearing a field name.

use serde_json::{json, Value};

/// The documented entry length.
const ENTRY_LEN: usize = 24;
/// Bytes of FILETIME at the front of an entry.
const FILETIME_LEN: usize = 8;

/// Which of the two layouts a SID key was found under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BamLayout {
    /// `Services\{bam,dam}\UserSettings\<SID>` — Windows 10 1803 and earlier.
    UserSettings,
    /// `Services\{bam,dam}\State\UserSettings\<SID>` — 1809 and later.
    StateUserSettings,
}

impl BamLayout {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserSettings => "usersettings",
            Self::StateUserSettings => "state_usersettings",
        }
    }
}

/// A recognised BAM/DAM per-SID key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BamSidKey {
    pub service: String,
    pub control_set: String,
    pub layout: BamLayout,
    pub sid: String,
}

/// Recognise a BAM/DAM per-SID key from its path.
///
/// Matched on **segments**, case-insensitively, because a hive holds either
/// casing and a substring match would catch a key merely named like one.
pub fn bam_sid_key(key_path: &str) -> Option<BamSidKey> {
    let segments: Vec<&str> = key_path
        .split('\\')
        .filter(|s| !s.is_empty())
        .skip(1) // the walk's synthetic root
        .collect();
    let lower: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();

    let services_at = lower.iter().position(|s| s == "services")?;
    let control_set = segments.get(services_at.checked_sub(1)?)?;
    if !control_set.to_ascii_lowercase().starts_with("controlset")
        && !control_set.eq_ignore_ascii_case("currentcontrolset")
    {
        return None;
    }
    let service = segments.get(services_at + 1)?;
    if !service.eq_ignore_ascii_case("bam") && !service.eq_ignore_ascii_case("dam") {
        return None;
    }
    // Either `…\<service>\UserSettings\<SID>` or `…\<service>\State\UserSettings\<SID>`.
    let (layout, sid_at) = match lower.get(services_at + 2).map(String::as_str) {
        Some("usersettings") => (BamLayout::UserSettings, services_at + 3),
        Some("state") if lower.get(services_at + 3).map(String::as_str) == Some("usersettings") => {
            (BamLayout::StateUserSettings, services_at + 4)
        }
        _ => return None,
    };
    // The SID key is the last segment: anything deeper is something else.
    if lower.len() != sid_at + 1 {
        return None;
    }
    Some(BamSidKey {
        service: service.to_ascii_lowercase(),
        control_set: control_set.to_string(),
        layout,
        sid: segments.get(sid_at)?.to_string(),
    })
}

/// Recognise a BAM/DAM **service** key — the container, not a per-SID leaf.
///
/// Its presence is what distinguishes "this hive predates BAM" from "BAM exists
/// and recorded nothing", and those are different facts. Returns
/// `(service, control_set, has_state_segment)`.
pub fn bam_service_key(key_path: &str) -> Option<(String, String, bool)> {
    let segments: Vec<&str> = key_path
        .split('\\')
        .filter(|s| !s.is_empty())
        .skip(1)
        .collect();
    let lower: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();
    let services_at = lower.iter().position(|s| s == "services")?;
    let control_set = segments.get(services_at.checked_sub(1)?)?;
    if !control_set.to_ascii_lowercase().starts_with("controlset")
        && !control_set.eq_ignore_ascii_case("currentcontrolset")
    {
        return None;
    }
    let service = segments.get(services_at + 1)?;
    if !service.eq_ignore_ascii_case("bam") && !service.eq_ignore_ascii_case("dam") {
        return None;
    }
    // The service key itself, or its `UserSettings` / `State\UserSettings`
    // container -- the three shapes whose existence answers the question.
    match lower.len().saturating_sub(services_at + 2) {
        0 => Some((service.to_ascii_lowercase(), control_set.to_string(), false)),
        1 if lower[services_at + 2] == "usersettings" => {
            Some((service.to_ascii_lowercase(), control_set.to_string(), true))
        }
        1 if lower[services_at + 2] == "state" => {
            Some((service.to_ascii_lowercase(), control_set.to_string(), false))
        }
        2 if lower[services_at + 2] == "state" && lower[services_at + 3] == "usersettings" => {
            Some((service.to_ascii_lowercase(), control_set.to_string(), true))
        }
        _ => None,
    }
}

/// Whether a value under a SID key is a program execution.
///
/// `Version` and `SequenceNumber` are BAM's own bookkeeping and sit on every
/// SID key. Publishing them as executed binaries would put two entries at the
/// top of every Windows 10 execution list this product ever produced — which is
/// `HUNT-122`: a rule that fires on the ordinary state of the system.
pub fn is_execution_value(name: &str) -> bool {
    !name.eq_ignore_ascii_case("Version") && !name.eq_ignore_ascii_case("SequenceNumber")
}

/// Whether the payload decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BamDecodeStatus {
    /// Exactly the documented 24 bytes.
    Decoded,
    /// Long enough for the FILETIME but not 24 bytes. The time is read and the
    /// length is stated.
    UnexpectedLength,
    /// Shorter than a FILETIME. No time, and the record says why.
    ShortRead,
}

impl BamDecodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Decoded => "decoded",
            Self::UnexpectedLength => "unexpected_length",
            Self::ShortRead => "short_read",
        }
    }
}

/// What the value name refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BamTargetKind {
    /// `\Device\HarddiskVolumeN\…` — an NT device path, reported as stored.
    NtDevicePath,
    /// A drive-lettered path.
    DosPath,
    /// A package family name. **Not a file path**: thirteen of the 26
    /// executions on a real Windows 10 hive are these, so a consumer assuming
    /// every BAM name is a path is wrong half the time.
    AppIdentity,
}

impl BamTargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NtDevicePath => "nt_device_path",
            Self::DosPath => "dos_path",
            Self::AppIdentity => "app_identity",
        }
    }
}

/// One decoded BAM/DAM execution.
#[derive(Clone, Debug)]
pub struct BamEntry {
    pub target: String,
    pub target_kind: BamTargetKind,
    pub last_executed: Option<String>,
    pub entry_length: u64,
    pub decode_status: BamDecodeStatus,
    pub content_incomplete_reason: Option<String>,
    /// The sixteen bytes after the FILETIME, kept and not named.
    pub trailing_bytes_hex: Option<String>,
    /// Always false in this build: the NT device name is not mapped.
    pub volume_resolved: bool,
    pub volume_note: Option<String>,
}

/// Decode one BAM/DAM value.
pub fn decode_entry(value_name: &str, data: &[u8]) -> BamEntry {
    let target_kind = classify_target(value_name);
    let (decode_status, incomplete) = match data.len() {
        ENTRY_LEN => (BamDecodeStatus::Decoded, None),
        n if n >= FILETIME_LEN => (
            BamDecodeStatus::UnexpectedLength,
            Some(seance_core::io::IncompleteReason::Unvalidated),
        ),
        _ => (
            BamDecodeStatus::ShortRead,
            Some(seance_core::io::IncompleteReason::ShortRead),
        ),
    };
    let last_executed = data
        .get(..FILETIME_LEN)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .and_then(seance_core::time::filetime_to_rfc3339);
    let trailing_bytes_hex = data
        .get(FILETIME_LEN..)
        .filter(|b| !b.is_empty())
        .map(|b| b.iter().map(|x| format!("{x:02x}")).collect());

    // The NT device name is what the hive holds. `MountedDevices` is in the
    // same hive and §2.6 owns that mapping.
    let volume_note = (target_kind == BamTargetKind::NtDevicePath).then(|| {
        "the NT device name is reported as stored; this build does not map it to a drive letter"
            .to_string()
    });

    BamEntry {
        target: value_name.to_string(),
        target_kind,
        last_executed,
        entry_length: data.len() as u64,
        decode_status,
        content_incomplete_reason: incomplete.map(|r| r.as_str().to_string()),
        trailing_bytes_hex,
        volume_resolved: false,
        volume_note,
    }
}

/// Classify a value name by its **shape**, never by the undocumented bytes.
fn classify_target(name: &str) -> BamTargetKind {
    if name.len() >= 8 && name[..8].eq_ignore_ascii_case(r"\Device\") {
        return BamTargetKind::NtDevicePath;
    }
    let b = name.as_bytes();
    let drive_lettered = b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.get(1) == Some(&b':')
        && matches!(b.get(2), Some(b'\\') | Some(b'/'));
    if drive_lettered {
        BamTargetKind::DosPath
    } else {
        BamTargetKind::AppIdentity
    }
}

impl BamEntry {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("BamEntry"));
        m.insert("name".into(), json!(self.target));
        m.insert("target".into(), json!(self.target));
        m.insert("target_kind".into(), json!(self.target_kind.as_str()));
        m.insert("last_executed".into(), json!(self.last_executed));
        m.insert("entry_length".into(), json!(self.entry_length));
        m.insert("decode_status".into(), json!(self.decode_status.as_str()));
        m.insert("volume_resolved".into(), json!(self.volume_resolved));
        if let Some(note) = &self.volume_note {
            m.insert("volume_note".into(), json!(note));
        }
        if let Some(hex) = &self.trailing_bytes_hex {
            m.insert("trailing_bytes_hex".into(), json!(hex));
            m.insert(
                "trailing_bytes_note".into(),
                json!(
                    "Sixteen bytes follow the timestamp and Microsoft documents none of \
                       them. They are kept as stored and name nothing: the target's kind \
                       above comes from the value name, not from these."
                ),
            );
        }
        if let Some(reason) = &self.content_incomplete_reason {
            m.insert("content_incomplete".into(), json!(true));
            m.insert("content_incomplete_reason".into(), json!(reason));
            m.insert(
                "content_incomplete_detail".into(),
                json!(format!(
                    "This value is {} bytes; a BAM entry is {ENTRY_LEN}. {}",
                    self.entry_length,
                    if self.last_executed.is_some() {
                        "The leading timestamp was read; nothing else was."
                    } else {
                        "It is shorter than a timestamp, so no execution time was read."
                    }
                )),
            );
        }
        Value::Object(m)
    }
}

/// What was found for one service, control set and (where relevant) SID.
///
/// The three absences this can state are all real, all distinct, and each
/// needs its own sentence — the key being absent, the key existing with nothing
/// under it, and a SID key holding only bookkeeping.
#[derive(Clone, Debug)]
pub struct BamCoverage {
    pub service: String,
    pub control_set: String,
    pub is_current_control_set: bool,
    pub service_key_present: bool,
    pub usersettings_present: bool,
    pub sid: Option<String>,
    pub values_total: usize,
    pub executions: usize,
    pub undecodable: usize,
}

impl BamCoverage {
    pub fn to_json(&self) -> Value {
        let service = &self.service;
        let note = if !self.service_key_present {
            format!(
                "This control set holds no {service} key. {} was introduced in Windows 10 \
                 1709, so a hive from an earlier build records none — that is the absence of \
                 the key, not the absence of executions.",
                service.to_uppercase()
            )
        } else if !self.usersettings_present {
            format!(
                "The {service} key exists and Windows recorded nothing under it: there are no \
                 per-user subkeys. That is a different fact from the key being absent."
            )
        } else if self.values_total == 0 {
            "This user's key exists and holds no values at all.".to_string()
        } else if self.executions == 0 {
            format!(
                "This user's key holds {} value(s), none of them an execution: BAM writes \
                 Version and SequenceNumber on every per-user key, and those are its own \
                 bookkeeping.",
                self.values_total
            )
        } else {
            format!(
                "{} execution(s) recorded for this user, out of {} value(s) on the key.",
                self.executions, self.values_total
            )
        };
        json!({
            "type": "BamCoverage",
            "name": match &self.sid {
                Some(sid) => format!("{service} {} {sid}", self.control_set),
                None => format!("{service} {}", self.control_set),
            },
            "service": service,
            "control_set": self.control_set,
            "is_current_control_set": self.is_current_control_set,
            "service_key_present": self.service_key_present,
            "usersettings_present": self.usersettings_present,
            "sid": self.sid,
            "values_total": self.values_total,
            "executions": self.executions,
            "undecodable": self.undecodable,
            "coverage_note": note,
        })
    }
}

/// Turn the walk's capture into records.
///
/// One `BamEntry` per execution value and one `BamCoverage` per SID key. Two
/// control sets holding `bam` are **both** emitted and distinguished by
/// `control_set` — never deduplicated. `HUNT-062`'s lesson: two copies of the
/// same machine's state are one machine, and the consumer must be able to see
/// which copy it is reading. Collapsing them would hide that an execution came
/// from the control set the machine did not boot.
pub fn emit(
    capture: &crate::resident::ResidentCapture,
    current_control_set: Option<u32>,
    control_sets_in_hive: &[String],
) -> Vec<Value> {
    use crate::resident::Anchor;
    use std::collections::BTreeSet;

    let is_current = |control_set: &str| match current_control_set {
        Some(n) => {
            control_set.eq_ignore_ascii_case("currentcontrolset")
                || control_set
                    .to_ascii_lowercase()
                    .strip_prefix("controlset")
                    .and_then(|d| d.parse::<u32>().ok())
                    == Some(n)
        }
        // Without `Select\Current` this build cannot say which control set the
        // machine booted, and claiming one would be a guess.
        None => false,
    };

    // What the walk saw of the container keys. Their presence is what separates
    // "this hive predates BAM" from "BAM exists and recorded nothing", and an
    // examiner asking whether anything ran is entitled to that difference.
    let mut service_keys: BTreeSet<(String, String)> = BTreeSet::new();
    let mut usersettings_keys: BTreeSet<(String, String)> = BTreeSet::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::BamService { .. })) {
        if let Anchor::BamService {
            service,
            control_set,
            is_usersettings,
        } = &key.anchor
        {
            service_keys.insert((service.clone(), control_set.clone()));
            if *is_usersettings {
                usersettings_keys.insert((service.clone(), control_set.clone()));
            }
        }
    }
    let mut sid_keys_seen: BTreeSet<(String, String)> = BTreeSet::new();

    let mut out = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::BamSid { .. })) {
        let Anchor::BamSid { key: sid_key } = &key.anchor else {
            continue;
        };
        let is_current = is_current(&sid_key.control_set);
        sid_keys_seen.insert((sid_key.service.clone(), sid_key.control_set.clone()));
        let mut coverage = BamCoverage {
            service: sid_key.service.clone(),
            control_set: sid_key.control_set.clone(),
            is_current_control_set: is_current,
            service_key_present: true,
            usersettings_present: true,
            sid: Some(sid_key.sid.clone()),
            values_total: key.values.len(),
            executions: 0,
            undecodable: 0,
        };
        for value in &key.values {
            if !is_execution_value(&value.name) {
                continue;
            }
            let entry = decode_entry(&value.name, &value.data);
            if entry.decode_status == BamDecodeStatus::ShortRead {
                coverage.undecodable += 1;
            }
            coverage.executions += 1;
            let mut record = entry.to_json();
            if let Some(m) = record.as_object_mut() {
                m.insert("service".into(), json!(sid_key.service));
                m.insert("control_set".into(), json!(sid_key.control_set));
                m.insert("is_current_control_set".into(), json!(is_current));
                m.insert("layout".into(), json!(sid_key.layout.as_str()));
                m.insert("sid".into(), json!(sid_key.sid));
                m.insert(
                    "sid_note".into(),
                    json!(
                        "the SID is reported as stored; this build does not resolve it to \
                           an account name"
                    ),
                );
                m.insert("key_path".into(), json!(key.key_path));
                m.insert(
                    "key_last_written".into(),
                    json!(seance_core::time::filetime_to_rfc3339(
                        key.last_written_filetime
                    )),
                );
            }
            out.push(record);
        }
        out.push(coverage.to_json());
    }

    // A container key with no per-SID subkey beneath it: Windows created it and
    // recorded nothing. Verified on a real Windows 10 hive, where `dam` exists
    // with zero subkeys.
    for (service, control_set) in &service_keys {
        if sid_keys_seen.contains(&(service.clone(), control_set.clone())) {
            continue;
        }
        out.push(
            BamCoverage {
                service: service.clone(),
                control_set: control_set.clone(),
                is_current_control_set: is_current(control_set),
                service_key_present: true,
                usersettings_present: usersettings_keys
                    .contains(&(service.clone(), control_set.clone())),
                sid: None,
                values_total: 0,
                executions: 0,
                undecodable: 0,
            }
            .to_json(),
        );
    }

    // And the absence that matters most: a hive with control sets and no BAM
    // key at all. Without this record a Windows 7 or XP `SYSTEM` hive yields
    // silence, and silence reads as "no programs ran" rather than as "this
    // build of Windows kept no such record". One per control set per service,
    // because each is a separate place the answer could have been.
    for control_set in control_sets_in_hive {
        for service in ["bam", "dam"] {
            if service_keys.contains(&(service.to_string(), control_set.clone())) {
                continue;
            }
            out.push(
                BamCoverage {
                    service: service.to_string(),
                    control_set: control_set.clone(),
                    is_current_control_set: is_current(control_set),
                    service_key_present: false,
                    usersettings_present: false,
                    sid: None,
                    values_total: 0,
                    executions: 0,
                    undecodable: 0,
                }
                .to_json(),
            );
        }
    }
    out
}
