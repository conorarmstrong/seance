//! UserAssist: what a user launched, how often, and when last.
//!
//! # What it is
//!
//! Explorer keeps a per-user tally of program launches — a run count, a focus
//! count, accumulated focus time, and the last execution — under
//! `NTUSER.DAT\…\Explorer\UserAssist\{GUID}\Count`. Value names are ROT13'd.
//! It is the closest thing Windows keeps to "this person ran this, this many
//! times, and last at this moment", and it outlives the program's deletion.
//!
//! `ROADMAP` §2.5.
//!
//! # The layout is published research, not documentation
//!
//! Microsoft documents none of this structure. The field names below come from
//! published DFIR research, and every record says so once, in
//! `layout_source`. The fields nobody has explained — ten floats and two spare
//! dwords in the 72-byte form — are kept as bytes rather than named, because a
//! named field is read as a fact.
//!
//! # Dispatch is on the data length, never on the declared version
//!
//! This is the one decision in the module that matters, and it is written
//! against a real trap. In `LoneWolf`'s
//! `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count` the key declares
//! `Version = 5` and 55 of its 56 values are 72 bytes — and `UEME_CTLSESSION`
//! is **1,612 bytes**. A decoder keyed on `Version` would read bytes
//! `0x3C..0x44` out of the middle of a session blob and publish them as an
//! execution time: a fabricated timestamp, in the one entry nobody would think
//! to check. That is the `HUNT-123` shape — a length trusted because a
//! neighbouring field said so.
//!
//! So the length decides, the declared version is cross-checked against it, and
//! a disagreement is reported rather than resolved.

use serde_json::{json, Value};

/// Length of the Windows 7 → 11 entry.
const WIN7_ENTRY_LEN: usize = 0x48;
/// Length of the Windows XP / 2003 entry.
const XP_ENTRY_LEN: usize = 16;
/// Length of the XP `UEME_CTLSESSION` bookkeeping entry.
const XP_SESSION_LEN: usize = 8;

/// Where the 72-byte form keeps its FILETIME.
const WIN7_FILETIME_AT: usize = 0x3C;
/// The undocumented run: ten floats, then a spare dword.
const WIN7_UNKNOWN_AT: usize = 0x10;

/// Whether the payload decoded, and if not, why not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeStatus {
    /// The length matched a known layout and every field it holds was read.
    Decoded,
    /// The length matches no layout this build knows. Nothing was decoded from
    /// the payload, and the record says so.
    UnrecognisedLength,
}

impl DecodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Decoded => "decoded",
            Self::UnrecognisedLength => "unrecognised_length",
        }
    }
}

/// What kind of entry the value name describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// Explorer's own counters — `UEME_CTLSESSION`, `UEME_CTLCUACount:ctor`.
    /// **Not a program execution.** Every non-empty `Count` key on a real
    /// Windows machine holds two of these, so reporting them as programs would
    /// put them at the top of every execution list ever produced — which is
    /// `HUNT-122`, a rule that fires on the ordinary state of the system.
    ExplorerBookkeeping,
    /// An executable, run by path (`UEME_RUNPATH:`).
    ExecutablePath,
    /// A shortcut (`UEME_RUNPIDL:`, or a Win7+ `{KNOWNFOLDERID}\…\x.lnk`).
    ShellLink,
    /// A control-panel applet (`UEME_RUNCPL:`).
    ControlPanel,
    /// Something launched, of a shape this build does not classify further.
    Launched,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExplorerBookkeeping => "explorer_bookkeeping",
            Self::ExecutablePath => "executable_path",
            Self::ShellLink => "shell_link",
            Self::ControlPanel => "control_panel",
            Self::Launched => "launched",
        }
    }
}

/// What the target names, when there is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    /// A drive-lettered path.
    DosPath,
    /// A shortcut, usually under a known folder.
    ShellLink,
    /// A UWP application identity: `Family_PublisherHash!AppId`.
    ///
    /// **Not a file path**, and must never be correlated against the
    /// filesystem: nothing would match, and the absence would read as a
    /// deleted program.
    AppIdentity,
    /// A control-panel applet name.
    ControlPanel,
    /// Named, but of no shape this build recognises.
    Unclassified,
    /// There is no target — bookkeeping.
    None,
}

impl TargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DosPath => "dos_path",
            Self::ShellLink => "shell_link",
            Self::AppIdentity => "app_identity",
            Self::ControlPanel => "control_panel",
            Self::Unclassified => "unclassified",
            Self::None => "none",
        }
    }
}

/// One decoded UserAssist value.
#[derive(Clone, Debug)]
pub struct UserAssistEntry {
    /// The stored value name, verbatim and un-rotated. Always present: these
    /// are the bytes that are in the evidence.
    pub value_name_raw: String,
    /// The name with ROT13 undone.
    pub name_decoded: String,
    pub entry_kind: EntryKind,
    pub target: Option<String>,
    pub target_kind: TargetKind,
    /// The known folder a `{KNOWNFOLDERID}` prefix names, when this build can
    /// name it from the published table.
    pub known_folder: Option<String>,
    pub session_id: Option<u32>,
    pub run_count: Option<u32>,
    /// Stated when the counter follows the XP convention.
    pub run_count_note: Option<String>,
    pub focus_count: Option<u32>,
    pub focus_time_ms: Option<u32>,
    pub last_executed: Option<String>,
    pub entry_length: u64,
    pub decode_status: DecodeStatus,
    /// Set when nothing could be decoded from the payload.
    pub content_incomplete_reason: Option<String>,
    /// The bytes of the fields nobody has published a meaning for.
    pub unknown_bytes_hex: Option<String>,
    /// Stated when the key's declared `Version` does not match the layout the
    /// length selected. The length is believed; this is the disagreement.
    pub version_disagreement: Option<String>,
    /// Said once per record, because the layout is not vendor-documented.
    pub layout_source: &'static str,
    /// Whether this row is a program execution — the only kind that earns a
    /// timeline event.
    pub is_execution: bool,
}

/// The one sentence every record carries about where its layout came from.
const LAYOUT_SOURCE: &str = "published format research, not vendor documentation";

/// The two `UserAssist` GUIDs whose meaning is published.
///
/// `LoneWolf` holds nine. Asserting a role for the seven nobody has documented
/// is how a tool comes to state what it cannot support, so they are reported in
/// full and classified `unclassified`.
pub fn guid_role(guid: &str) -> &'static str {
    let g = guid.trim().to_ascii_uppercase();
    match g.as_str() {
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}" => "executable_execution",
        "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" => "shortcut_execution",
        _ => "unclassified",
    }
}

/// Known folders this build can name, from the published `KNOWNFOLDERID` set.
///
/// Deliberately short. A GUID absent from this table keeps its GUID and claims
/// nothing, because a folder named wrongly is worse than one not named.
const KNOWN_FOLDERS: &[(&str, &str)] = &[
    ("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "Common Programs"),
    ("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "Programs"),
    ("{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "User Pinned"),
];

/// Undo ROT13 over ASCII letters only.
///
/// Non-ASCII bytes are untouched: a UTF-16 or mojibake name must survive to the
/// record even when the decode makes no sense of it. `value_name_raw` keeps the
/// stored form regardless.
fn rot13(bytes: &[u8]) -> String {
    let rotated: Vec<u8> = bytes
        .iter()
        .map(|b| match b {
            b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
            other => *other,
        })
        .collect();
    String::from_utf8_lossy(&rotated).into_owned()
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn le_u64(data: &[u8], at: usize) -> Option<u64> {
    data.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Classify a decoded name into what ran and what it names.
fn classify(name: &str) -> (EntryKind, Option<String>, TargetKind, Option<String>) {
    // Explorer's own counters. Checked first, because `UEME_CTLCUACount:ctor`
    // would otherwise fall through to a prefix match.
    if name.starts_with("UEME_CTL") {
        return (EntryKind::ExplorerBookkeeping, None, TargetKind::None, None);
    }
    for (prefix, kind, target_kind) in [
        (
            "UEME_RUNPATH:",
            EntryKind::ExecutablePath,
            TargetKind::DosPath,
        ),
        ("UEME_RUNPIDL:", EntryKind::ShellLink, TargetKind::ShellLink),
        (
            "UEME_RUNCPL:",
            EntryKind::ControlPanel,
            TargetKind::ControlPanel,
        ),
    ] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return (kind, Some(rest.to_string()), target_kind, None);
        }
    }
    // Windows 7+: a `{KNOWNFOLDERID}` prefix, then a path under it.
    if name.starts_with('{') {
        if let Some(end) = name.find('}') {
            let guid = &name[..=end];
            let folder = KNOWN_FOLDERS
                .iter()
                .find(|(g, _)| g.eq_ignore_ascii_case(guid))
                .map(|(_, n)| n.to_string());
            let kind = if name.to_ascii_lowercase().ends_with(".lnk") {
                TargetKind::ShellLink
            } else {
                TargetKind::Unclassified
            };
            return (EntryKind::ShellLink, Some(name.to_string()), kind, folder);
        }
    }
    // A UWP application identity: `Family_PublisherHash!AppId`. Not a path.
    if name.contains('!') && !name.contains('\\') && !name.contains('/') {
        return (
            EntryKind::Launched,
            Some(name.to_string()),
            TargetKind::AppIdentity,
            None,
        );
    }
    let bytes = name.as_bytes();
    let drive_lettered = bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && matches!(bytes.get(2), Some(b'\\') | Some(b'/'));
    if drive_lettered {
        return (
            EntryKind::ExecutablePath,
            Some(name.to_string()),
            TargetKind::DosPath,
            None,
        );
    }
    (
        EntryKind::Launched,
        Some(name.to_string()),
        TargetKind::Unclassified,
        None,
    )
}

/// Decode one UserAssist value.
///
/// No hive or artifact types in the signature, so the layout can be stated by a
/// test on its own terms and so the memory stack can reuse this later against
/// a hive recovered from a capture.
pub fn decode_entry(
    name_bytes: &[u8],
    data: &[u8],
    declared_version: Option<u32>,
) -> UserAssistEntry {
    let name_decoded = rot13(name_bytes);
    let (entry_kind, target, target_kind, known_folder) = classify(&name_decoded);

    let mut e = UserAssistEntry {
        value_name_raw: String::from_utf8_lossy(name_bytes).into_owned(),
        name_decoded,
        entry_kind,
        target,
        target_kind,
        known_folder,
        session_id: None,
        run_count: None,
        run_count_note: None,
        focus_count: None,
        focus_time_ms: None,
        last_executed: None,
        entry_length: data.len() as u64,
        decode_status: DecodeStatus::UnrecognisedLength,
        content_incomplete_reason: None,
        unknown_bytes_hex: None,
        version_disagreement: None,
        layout_source: LAYOUT_SOURCE,
        // Bookkeeping is never an execution, whatever the payload holds.
        is_execution: entry_kind != EntryKind::ExplorerBookkeeping,
    };

    // The LENGTH decides. See the module comment: a 1,612-byte session blob
    // sits under a key declaring version 5, and reading it at the 72-byte
    // offsets would publish a timestamp from the middle of it.
    let layout_version = match data.len() {
        WIN7_ENTRY_LEN => {
            e.decode_status = DecodeStatus::Decoded;
            e.session_id = le_u32(data, 0x00);
            e.run_count = le_u32(data, 0x04);
            e.focus_count = le_u32(data, 0x08);
            e.focus_time_ms = le_u32(data, 0x0C);
            // A zero FILETIME is the absence of a time. `filetime_to_rfc3339`
            // already refuses the 0 sentinel, which is why it is asked rather
            // than formatted here.
            e.last_executed =
                le_u64(data, WIN7_FILETIME_AT).and_then(seance_core::time::filetime_to_rfc3339);
            // Ten floats and a spare dword, none of them published. Kept as
            // bytes: a named field is read as a fact.
            e.unknown_bytes_hex = Some(hex(&data[WIN7_UNKNOWN_AT..WIN7_FILETIME_AT]));
            Some(5)
        }
        XP_ENTRY_LEN => {
            e.decode_status = DecodeStatus::Decoded;
            e.session_id = le_u32(data, 0x00);
            e.run_count = le_u32(data, 0x04);
            e.last_executed = le_u64(data, 0x08).and_then(seance_core::time::filetime_to_rfc3339);
            // The XP counter is documented as starting at 5. Stated, never
            // applied: a report that says 14 runs where the hive says 19 is
            // asserting a convention as a fact.
            e.run_count_note = Some(
                "Windows XP-era UserAssist counters are documented as starting at 5; this is \
                 the value stored, not adjusted."
                    .to_string(),
            );
            // The XP layout holds neither focus field, and a zero would be a
            // fabrication rather than a reading.
            Some(3)
        }
        XP_SESSION_LEN => {
            e.decode_status = DecodeStatus::Decoded;
            e.session_id = le_u32(data, 0x00);
            e.run_count = le_u32(data, 0x04);
            // Eight bytes hold no FILETIME.
            Some(3)
        }
        _ => {
            e.content_incomplete_reason = Some(
                seance_core::io::IncompleteReason::UnresolvedStructure
                    .as_str()
                    .to_string(),
            );
            // Nothing was decoded, so nothing may be presented — including a
            // timeline event.
            e.is_execution = false;
            None
        }
    };

    if let (Some(declared), Some(layout)) = (declared_version, layout_version) {
        if declared != layout {
            e.version_disagreement = Some(format!(
                "This key declares version {declared}, and this value's {} bytes are the \
                 version {layout} layout. The length was believed, because a version field \
                 does not change what the bytes are.",
                data.len()
            ));
        }
    }
    e
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl UserAssistEntry {
    /// The record this entry becomes.
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("UserAssistEntry"));
        m.insert("name".into(), json!(self.name_decoded));
        m.insert("value_name_raw".into(), json!(self.value_name_raw));
        m.insert("name_decoded".into(), json!(self.name_decoded));
        m.insert("entry_kind".into(), json!(self.entry_kind.as_str()));
        m.insert("target".into(), json!(self.target));
        m.insert("target_kind".into(), json!(self.target_kind.as_str()));
        m.insert("known_folder".into(), json!(self.known_folder));
        m.insert("session_id".into(), json!(self.session_id));
        m.insert("run_count".into(), json!(self.run_count));
        m.insert("focus_count".into(), json!(self.focus_count));
        m.insert("focus_time_ms".into(), json!(self.focus_time_ms));
        m.insert("last_executed".into(), json!(self.last_executed));
        m.insert("entry_length".into(), json!(self.entry_length));
        m.insert("decode_status".into(), json!(self.decode_status.as_str()));
        m.insert("is_execution".into(), json!(self.is_execution));
        m.insert("layout_source".into(), json!(self.layout_source));
        if let Some(note) = &self.run_count_note {
            m.insert("run_count_note".into(), json!(note));
        }
        if let Some(hex) = &self.unknown_bytes_hex {
            m.insert("unknown_bytes_hex".into(), json!(hex));
        }
        if let Some(why) = &self.version_disagreement {
            m.insert("version_disagreement".into(), json!(why));
        }
        if let Some(reason) = &self.content_incomplete_reason {
            m.insert("content_incomplete".into(), json!(true));
            m.insert("content_incomplete_reason".into(), json!(reason));
            m.insert(
                "content_incomplete_detail".into(),
                json!(format!(
                    "This value is {} bytes, which matches no UserAssist layout this build \
                     knows. Nothing was decoded from it: the counts and the last-execution \
                     time are absent from this record and present in the hive.",
                    self.entry_length
                )),
            );
        }
        Value::Object(m)
    }
}

/// What was found under one `UserAssist\{GUID}` key.
///
/// The point of this record is the absence it can state. Seven of `LoneWolf`'s
/// nine `Count` keys hold nothing, and *Windows recorded nothing here* is a
/// different sentence from *this build did not look*.
#[derive(Clone, Debug)]
pub struct UserAssistCoverage {
    pub guid: String,
    pub declared_version: Option<u32>,
    pub count_key_present: bool,
    pub values_total: usize,
    pub entries_decoded: usize,
    pub entries_undecodable: usize,
    pub bookkeeping_values: usize,
}

impl UserAssistCoverage {
    pub fn to_json(&self) -> Value {
        let note = if !self.count_key_present {
            "This GUID has no Count key, so Windows kept no tally under it at all."
        } else if self.values_total == 0 {
            "Windows recorded nothing under this GUID: its Count key exists and is empty. \
             That is not the same as this build not having looked."
        } else if self.entries_undecodable > 0 {
            "Some values under this GUID are of a length this build does not decode; each is \
             recorded with its length and nothing read from it."
        } else {
            "Every value under this GUID decoded."
        };
        json!({
            "type": "UserAssistCoverage",
            "name": format!("UserAssist {}", self.guid),
            "guid": self.guid,
            "guid_role": guid_role(&self.guid),
            "declared_version": self.declared_version,
            "count_key_present": self.count_key_present,
            "values_total": self.values_total,
            "entries_decoded": self.entries_decoded,
            "entries_undecodable": self.entries_undecodable,
            "bookkeeping_values": self.bookkeeping_values,
            "coverage_note": note,
            "layout_source": LAYOUT_SOURCE,
        })
    }
}

/// Turn the walk's capture into records.
///
/// One `UserAssistEntry` per value under a `Count` key, and one
/// `UserAssistCoverage` per GUID key — including the GUIDs whose `Count` key is
/// empty, which is 7 of the 9 on a real `LoneWolf` `NTUSER.DAT`. Those empty
/// ones are the point: *Windows recorded nothing here* is a different sentence
/// from *this build did not look*, and only a coverage record can say the
/// first.
pub fn emit(capture: &crate::resident::ResidentCapture) -> Vec<Value> {
    use crate::resident::Anchor;
    use std::collections::BTreeMap;

    // The declared `Version`, per GUID, from the GUID key's one value.
    let mut declared: BTreeMap<String, Option<u32>> = BTreeMap::new();
    let mut guid_keys: Vec<String> = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::UserAssistGuid { .. })) {
        if let Anchor::UserAssistGuid { guid } = &key.anchor {
            let version = key
                .values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case("Version"))
                .and_then(|v| v.data.get(..4))
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes);
            declared.insert(guid.clone(), version);
            guid_keys.push(guid.clone());
        }
    }

    let mut out = Vec::new();
    let mut seen_count_keys: BTreeMap<String, UserAssistCoverage> = BTreeMap::new();

    for key in capture.keys_matching(|a| matches!(a, Anchor::UserAssistCount { .. })) {
        let Anchor::UserAssistCount { guid } = &key.anchor else {
            continue;
        };
        let version = declared.get(guid).copied().flatten();
        let mut coverage = UserAssistCoverage {
            guid: guid.clone(),
            declared_version: version,
            count_key_present: true,
            values_total: key.values.len(),
            entries_decoded: 0,
            entries_undecodable: 0,
            bookkeeping_values: 0,
        };
        for value in &key.values {
            let entry = decode_entry(value.name.as_bytes(), &value.data, version);
            match entry.decode_status {
                DecodeStatus::Decoded => coverage.entries_decoded += 1,
                DecodeStatus::UnrecognisedLength => coverage.entries_undecodable += 1,
            }
            if entry.entry_kind == EntryKind::ExplorerBookkeeping {
                coverage.bookkeeping_values += 1;
            }
            let mut record = entry.to_json();
            if let Some(m) = record.as_object_mut() {
                m.insert("guid".into(), json!(guid));
                m.insert("guid_role".into(), json!(guid_role(guid)));
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
        seen_count_keys.insert(guid.clone(), coverage);
    }

    // A GUID key with no `Count` subkey at all is the other absence, and it is
    // reported rather than left out.
    for guid in guid_keys {
        let coverage = seen_count_keys.remove(&guid).unwrap_or(UserAssistCoverage {
            declared_version: declared.get(&guid).copied().flatten(),
            guid: guid.clone(),
            count_key_present: false,
            values_total: 0,
            entries_decoded: 0,
            entries_undecodable: 0,
            bookkeeping_values: 0,
        });
        out.push(coverage.to_json());
    }
    // A `Count` key whose GUID parent was never walked -- a damaged index, or a
    // cap -- still gets its coverage record.
    for (_, coverage) in seen_count_keys {
        out.push(coverage.to_json());
    }
    out
}
