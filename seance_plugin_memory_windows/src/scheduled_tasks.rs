//! Scheduled tasks from the in-memory SOFTWARE hive (`ROADMAP` §5.3,
//! upstream's `scheduled_tasks`).
//!
//! # What an examiner learns
//!
//! Every task the Task Scheduler had registered, as the registry in RAM held
//! it: the task's path, what it runs (`Actions`), when it was created and last
//! ran and with what result (`DynamicInfo`), and who authored it. Persistence
//! by scheduled task is the second most common kind after a service, and the
//! in-memory hive is what the machine was *using* — a task deleted from disk
//! after the fact, or one whose on-disk XML was edited, is still here as the
//! scheduler saw it.
//!
//! # Where it comes from
//!
//! `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
//! holds one subkey per task, named by GUID, with the task's values. The
//! hive is opened through the same cell reader every other registry stage
//! uses, so a value whose data was paged out is reported as unavailable and
//! never as empty.
//!
//! # The three binary blobs, and how far each is decoded
//!
//! `Actions` is a small serialisation: a version word (3), the author as a
//! length-prefixed UTF-16 string, then one record per action introduced by a
//! magic word — `0x6666` runs a program, `0x7777` a COM handler, `0x8888`
//! sends mail, `0x9999` shows a message. Every string is length-prefixed, so
//! the decode is bounded by the blob's own fields and refuses a string that
//! runs past its end rather than truncating it into a plausible command. An
//! action kind this decoder does not know stops the decode, with the kind and
//! the byte count of what follows on the record.
//!
//! `DynamicInfo` is fixed-layout: a magic double-word, the creation time and
//! the last run time as FILETIMEs, a state word, the last result code, and on
//! newer builds the last successful run time. Decoded by length, and a zero
//! time is an absent time, never 1601. Both layouts were read from public
//! descriptions of the format and checked against the tasks in this project's
//! Windows 11 26200 capture.
//!
//! `Triggers` — when the task fires — is decoded in
//! [`crate::scheduled_tasks_triggers`], from the same kind of public
//! description, with every one of the capture's 246 blobs decoding to its
//! last byte; the blob's length stays on the record beside it.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::Incomplete;
use serde_json::{json, Value};

use crate::amcache::WinTime;
use crate::profile::WindowsProfile;
use crate::registry::hivelist::list_hives;
use crate::registry::key::{CellReader, RegistryData, ValueData};
use crate::registry::printkey::{print_key, KeyListing};
use crate::registry::space::{locate_bin_space, HiveSpace};
pub use crate::scheduled_tasks_triggers::{
    decode_triggers, TaskTrigger, TaskTriggers, TriggerKind,
};

/// The hive.
pub const HIVE_SOFTWARE: &str = "SOFTWARE";
/// The key holding one subkey per task.
pub const KEY_TASKS: &str = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks";
/// Tasks this stage will read. A machine has a few hundred.
pub const MAX_TASKS: usize = 16_384;
/// Actions one blob may declare before the decode stops.
const MAX_ACTIONS: usize = 256;
/// Longest string a blob may declare.
const MAX_STRING_BYTES: u32 = 1 << 16;

/// One action a task performs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskAction {
    Exec {
        id: String,
        command: String,
        arguments: String,
        working_directory: String,
        flags: u16,
    },
    ComHandler {
        id: String,
        class_id: String,
        data: String,
    },
    Email {
        id: String,
        from: String,
        to: String,
        subject: String,
    },
    MessageBox {
        id: String,
        title: String,
        body: String,
    },
}

impl TaskAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Exec { .. } => "exec",
            Self::ComHandler { .. } => "com_handler",
            Self::Email { .. } => "email",
            Self::MessageBox { .. } => "message_box",
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Exec {
                id,
                command,
                arguments,
                working_directory,
                flags,
            } => json!({
                "kind": "exec", "id": id, "command": command, "arguments": arguments,
                "working_directory": working_directory, "flags": flags,
            }),
            Self::ComHandler { id, class_id, data } => {
                json!({"kind": "com_handler", "id": id, "class_id": class_id, "data": data})
            }
            Self::Email {
                id,
                from,
                to,
                subject,
            } => json!({
                "kind": "email", "id": id, "from": from, "to": to, "subject": subject,
                "note": "only the first three strings of a mail action are decoded",
            }),
            Self::MessageBox { id, title, body } => {
                json!({"kind": "message_box", "id": id, "title": title, "body": body})
            }
        }
    }
}

/// A decoded `Actions` blob.
#[derive(Debug, Clone, Default)]
pub struct TaskActions {
    pub version: u16,
    pub author: String,
    pub actions: Vec<TaskAction>,
    /// An action magic the decoder does not know, which stopped the decode.
    pub unknown_kind: Option<u16>,
    /// A record that would not decode, which stopped the decode.
    pub malformed: Option<String>,
    /// Bytes after the last decoded record.
    pub trailing_bytes: usize,
}

impl TaskActions {
    pub fn to_json(&self) -> Value {
        json!({
            "version": self.version,
            "author": self.author,
            "actions": self.actions.iter().map(TaskAction::to_json).collect::<Vec<_>>(),
            "actions_total": self.actions.len(),
            "unknown_kind": self.unknown_kind,
            "malformed": self.malformed,
            "trailing_bytes": self.trailing_bytes,
            "complete": self.unknown_kind.is_none() && self.malformed.is_none() && self.trailing_bytes == 0,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn u16(&mut self) -> Result<u16, String> {
        let b = self
            .bytes
            .get(self.at..self.at + 2)
            .ok_or_else(|| format!("a 16-bit field at {} runs past the end", self.at))?;
        self.at += 2;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or_else(|| format!("a 32-bit field at {} runs past the end", self.at))?;
        self.at += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length-prefixed UTF-16LE string: the length is in bytes.
    fn string(&mut self) -> Result<String, String> {
        let start = self.at;
        let len = self.u32()?;
        if len > MAX_STRING_BYTES {
            return Err(format!(
                "a string at {start} declares {len} byte(s), above the {MAX_STRING_BYTES} this \
                 decoder will read"
            ));
        }
        let len = len as usize;
        let b = self
            .bytes
            .get(self.at..self.at + len)
            .ok_or_else(|| format!("a string at {start} of {len} byte(s) runs past the end"))?;
        self.at += len;
        let units: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes(*p))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    fn guid(&mut self) -> Result<String, String> {
        let b = self
            .bytes
            .get(self.at..self.at + 16)
            .ok_or_else(|| format!("a class id at {} runs past the end", self.at))?;
        self.at += 16;
        Ok(format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        ))
    }
}

/// Decode an `Actions` blob.
///
/// # Errors
///
/// A blob too short for its header, or of a version other than 3. A record
/// that will not decode after the header is not an error: what decoded before
/// it is returned with the reason on [`TaskActions::malformed`].
pub fn decode_actions(blob: &[u8]) -> Result<TaskActions, String> {
    let mut cursor = Cursor { bytes: blob, at: 0 };
    let version = cursor.u16()?;
    if version != 3 {
        return Err(format!(
            "the Actions blob is version {version}; only version 3 is decoded"
        ));
    }
    let author = cursor.string()?;
    let mut out = TaskActions {
        version,
        author,
        ..TaskActions::default()
    };
    while cursor.at < blob.len() {
        if out.actions.len() >= MAX_ACTIONS {
            out.malformed = Some(format!(
                "more than {MAX_ACTIONS} actions; the decode stopped"
            ));
            break;
        }
        let record_at = cursor.at;
        let kind = match cursor.u16() {
            Ok(kind) => kind,
            Err(err) => {
                out.malformed = Some(err);
                cursor.at = record_at;
                break;
            }
        };
        let decoded = match kind {
            0x6666 => cursor.string().and_then(|id| {
                Ok(TaskAction::Exec {
                    id,
                    command: cursor.string()?,
                    arguments: cursor.string()?,
                    working_directory: cursor.string()?,
                    flags: cursor.u16()?,
                })
            }),
            0x7777 => cursor.string().and_then(|id| {
                Ok(TaskAction::ComHandler {
                    id,
                    class_id: cursor.guid()?,
                    data: cursor.string()?,
                })
            }),
            0x8888 => cursor.string().and_then(|id| {
                Ok(TaskAction::Email {
                    id,
                    from: cursor.string()?,
                    to: cursor.string()?,
                    subject: cursor.string()?,
                })
            }),
            0x9999 => cursor.string().and_then(|id| {
                Ok(TaskAction::MessageBox {
                    id,
                    title: cursor.string()?,
                    body: cursor.string()?,
                })
            }),
            other => {
                out.unknown_kind = Some(other);
                cursor.at = record_at;
                break;
            }
        };
        match decoded {
            Ok(action) => {
                out.actions.push(action);
                // A mail action carries more strings than are decoded; the
                // rest of the blob is counted as trailing rather than parsed
                // as further actions.
                if matches!(out.actions.last(), Some(TaskAction::Email { .. })) {
                    break;
                }
            }
            Err(err) => {
                out.malformed = Some(err);
                cursor.at = record_at;
                break;
            }
        }
    }
    out.trailing_bytes = blob.len().saturating_sub(cursor.at);
    Ok(out)
}

/// A decoded `DynamicInfo` blob.
#[derive(Debug, Clone)]
pub struct DynamicInfo {
    pub magic: u32,
    pub creation: Option<WinTime>,
    pub last_run: Option<WinTime>,
    pub state: Option<u32>,
    pub last_result: Option<u32>,
    pub last_successful_run: Option<WinTime>,
    pub length: usize,
}

impl DynamicInfo {
    pub fn to_json(&self) -> Value {
        json!({
            "magic": self.magic,
            "creation": self.creation.as_ref().map(WinTime::to_json),
            "last_run": self.last_run.as_ref().map(WinTime::to_json),
            "state": self.state,
            "last_result": self.last_result.map(|r| format!("{r:#010x}")),
            "last_successful_run": self.last_successful_run.as_ref().map(WinTime::to_json),
            "length": self.length,
        })
    }
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|p| u32::from_le_bytes([p[0], p[1], p[2], p[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8)
        .map(|p| u64::from_le_bytes(p.try_into().expect("eight bytes")))
}

/// Decode a `DynamicInfo` blob by its length.
///
/// # Errors
///
/// A blob shorter than the 28 bytes the first four fields take.
pub fn decode_dynamic_info(blob: &[u8]) -> Result<DynamicInfo, String> {
    if blob.len() < 28 {
        return Err(format!(
            "DynamicInfo is {} byte(s); the fields take at least 28",
            blob.len()
        ));
    }
    let time = |at: usize| u64_at(blob, at).and_then(WinTime::from_filetime);
    Ok(DynamicInfo {
        magic: u32_at(blob, 0).unwrap_or(0),
        creation: time(4),
        last_run: time(12),
        state: u32_at(blob, 20),
        last_result: u32_at(blob, 24),
        last_successful_run: if blob.len() >= 36 { time(28) } else { None },
        length: blob.len(),
    })
}

/// A value's data as this stage saw it.
#[derive(Debug, Clone)]
pub enum TaskValue {
    Text(String),
    Dword(u32),
    Binary(Vec<u8>),
    Unavailable(String),
    Absent,
}

impl TaskValue {
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn binary(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(b) => Some(b),
            _ => None,
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Text(t) => json!({"kind": "text", "text": t}),
            Self::Dword(d) => json!({"kind": "dword", "value": d}),
            Self::Binary(b) => json!({"kind": "binary", "length": b.len()}),
            Self::Unavailable(why) => json!({"kind": "unavailable", "detail": why}),
            Self::Absent => json!({"kind": "absent"}),
        }
    }
}

/// One task.
#[derive(Debug, Clone)]
pub struct ScheduledTask {
    /// The subkey's name: the task's GUID.
    pub id: String,
    pub path: TaskValue,
    pub uri: TaskValue,
    pub author: TaskValue,
    pub description: TaskValue,
    pub date: TaskValue,
    pub schema: TaskValue,
    pub version: TaskValue,
    pub hash: TaskValue,
    pub actions: Option<TaskActions>,
    pub actions_error: Option<String>,
    pub dynamic_info: Option<DynamicInfo>,
    pub dynamic_info_error: Option<String>,
    /// The `Triggers` blob's length.
    pub triggers_length: Option<usize>,
    /// The `Triggers` blob decoded: when the task fires.
    pub triggers: Option<TaskTriggers>,
    /// Why it was not decoded, when it was not.
    pub triggers_error: Option<String>,
    /// Value names on the key this stage does not read.
    pub other_values: Vec<String>,
    /// Whether every value of the key was read.
    pub complete: bool,
    pub notes: Vec<String>,
}

impl ScheduledTask {
    /// The command an exec action runs, when there is one.
    pub fn first_command(&self) -> Option<&str> {
        self.actions.as_ref()?.actions.iter().find_map(|a| match a {
            TaskAction::Exec { command, .. } => Some(command.as_str()),
            _ => None,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemoryScheduledTask",
            "name": self.path.text().map(str::to_string).unwrap_or_else(|| self.id.clone()),
            "id": self.id,
            "path": self.path.to_json(),
            "uri": self.uri.to_json(),
            "author": self.author.to_json(),
            "description": self.description.to_json(),
            "date": self.date.to_json(),
            "schema": self.schema.to_json(),
            "version": self.version.to_json(),
            "hash": self.hash.to_json(),
            "actions": self.actions.as_ref().map(TaskActions::to_json),
            "actions_error": self.actions_error,
            "dynamic_info": self.dynamic_info.as_ref().map(DynamicInfo::to_json),
            "dynamic_info_error": self.dynamic_info_error,
            "triggers_length": self.triggers_length,
            "triggers": self.triggers.as_ref().map(TaskTriggers::to_json),
            "triggers_error": self.triggers_error,
            "other_values": self.other_values,
            "complete": self.complete,
            "notes": self.notes,
        })
    }
}

/// What one survey produced.
#[derive(Debug, Clone)]
pub struct ScheduledTaskSurvey {
    /// Where the SOFTWARE hive was, when it was found.
    pub hive: Option<u64>,
    /// Why nothing was read, when nothing was.
    pub unavailable: Option<String>,
    /// Whether the hive list itself was walked end to end.
    pub hive_list_complete: bool,
    pub tasks: Vec<ScheduledTask>,
    /// Subkeys the `Tasks` key declares.
    pub tasks_declared: Option<u64>,
    /// Whether the `Tasks` key's subkey index was read in full.
    pub tasks_index_complete: bool,
    pub capped: bool,
}

impl ScheduledTaskSurvey {
    pub fn tasks_with_actions(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.actions.as_ref().is_some_and(|a| !a.actions.is_empty()))
            .count()
    }

    /// Tasks whose `Triggers` blob decoded to its last byte.
    pub fn tasks_with_triggers_whole(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.triggers.as_ref().is_some_and(TaskTriggers::is_whole))
            .count()
    }

    /// Tasks holding a `Triggers` blob that did not decode whole.
    pub fn tasks_with_triggers_undecoded(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| {
                t.triggers_length.is_some()
                    && !t.triggers.as_ref().is_some_and(TaskTriggers::is_whole)
            })
            .count()
    }

    pub fn is_complete(&self) -> bool {
        self.tasks_with_triggers_undecoded() == 0
            && self.unavailable.is_none()
            && self.hive_list_complete
            && self.tasks_index_complete
            && !self.capped
            && self.tasks.iter().all(|t| t.complete)
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(why) = &self.unavailable {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("no task was read: {why}"),
            ));
        }
        if !self.hive_list_complete {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                "the hive list did not walk end to end, so the SOFTWARE hive may have been \
                 missed rather than absent"
                    .to_string(),
            ));
        }
        if !self.tasks_index_complete {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                "the Tasks key's subkey index was not read in full, so this is not every task"
                    .to_string(),
            ));
        }
        if self.capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!("only the first {MAX_TASKS} tasks were read"),
            ));
        }
        let undecoded = self.tasks_with_triggers_undecoded();
        if undecoded > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{undecoded} task(s) hold a Triggers blob that did not decode to its end \
                     (each says where and why), so when those tasks fire is not fully stated"
                ),
            ));
        }
        let partial = self.tasks.iter().filter(|t| !t.complete).count();
        if partial > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{partial} task(s) had a value whose data could not be read; a missing \
                     command there is not a task that runs nothing"
                ),
            ));
        }
        out
    }

    pub fn describe(&self) -> String {
        match &self.unavailable {
            Some(why) => format!("No scheduled task was read: {why}"),
            None => format!(
                "{} scheduled task(s) read from the TaskCache in the in-memory SOFTWARE hive \
                 ({} declared); {} carry a decoded action list.",
                self.tasks.len(),
                self.tasks_declared
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "an unknown number".to_string()),
                self.tasks_with_actions()
            ),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "hive": self.hive.map(|h| format!("{h:#018x}")),
            "hive_name": HIVE_SOFTWARE,
            "key": KEY_TASKS,
            "unavailable": self.unavailable,
            "hive_list_complete": self.hive_list_complete,
            "tasks": self.tasks.iter().map(ScheduledTask::to_json).collect::<Vec<_>>(),
            "tasks_total": self.tasks.len(),
            "tasks_declared": self.tasks_declared,
            "tasks_index_complete": self.tasks_index_complete,
            "tasks_with_actions": self.tasks_with_actions(),
            "tasks_with_triggers_whole": self.tasks_with_triggers_whole(),
            "tasks_with_triggers_undecoded": self.tasks_with_triggers_undecoded(),
            "capped": self.capped,
            "decode_basis":
                "`Actions` is decoded record by record from its own length-prefixed strings \
                 (version 3 only; exec, COM handler, mail and message-box records; an unknown \
                 kind stops the decode and is named). `DynamicInfo` is decoded by length: magic, \
                 creation and last-run FILETIMEs, state, last result, and the last successful \
                 run where 36 bytes are present. Both layouts come from public descriptions and \
                 were checked against the tasks in this project's Windows 11 26200 capture. \
                 `Triggers` is decoded from the same public description: a header, the job \
                 bucket (flags, the XML's CRC32, principal, user), and one record per trigger by \
                 magic (time with its schedule mode, boot, logon, idle, registration, session \
                 state change, event with its XPath subscription, WNF state change); every one \
                 of the 246 blobs on the 26200 capture decodes to its last byte. An unknown \
                 trigger kind, or a record that runs past the blob, stops the decode with what \
                 came before kept and the stop stated. A boundary marked localized is the \
                 wall-clock time in the machine's zone and is printed with no zone, never as \
                 UTC; a zero or all-ones time is absent.",
            "statement": self.describe(),
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Read every task from the in-memory SOFTWARE hive.
pub fn survey_scheduled_tasks(profile: &WindowsProfile) -> ScheduledTaskSurvey {
    let mut survey = ScheduledTaskSurvey {
        hive: None,
        unavailable: None,
        hive_list_complete: false,
        tasks: Vec::new(),
        tasks_declared: None,
        tasks_index_complete: false,
        capped: false,
    };
    let listing = match list_hives(profile) {
        Ok(listing) => listing,
        Err(err) => {
            survey.unavailable = Some(format!("the hive list could not be walked: {err}"));
            return survey;
        }
    };
    survey.hive_list_complete = listing.is_complete();
    let Some(record) = listing.hives.iter().find(|hive| {
        hive.name
            .file_name()
            .is_some_and(|file| file.eq_ignore_ascii_case(HIVE_SOFTWARE))
    }) else {
        survey.unavailable = Some(format!(
            "no hive named {HIVE_SOFTWARE} is on the loaded-hive list{}",
            if listing.is_complete() {
                ""
            } else {
                ", which was not walked in full"
            }
        ));
        return survey;
    };
    survey.hive = Some(record.address);
    let bins = locate_bin_space(profile);
    let hive = match HiveSpace::open_with_bin_space(profile, record.address, &bins) {
        Ok(hive) => hive,
        Err(err) => {
            survey.unavailable = Some(format!(
                "the {HIVE_SOFTWARE} hive at {:#x} could not be opened: {err}",
                record.address
            ));
            return survey;
        }
    };
    let reader = match CellReader::new(Arc::clone(&hive)) {
        Ok(reader) => reader,
        Err(err) => {
            survey.unavailable = Some(format!("the hive's cells could not be read: {err}"));
            return survey;
        }
    };
    let tasks_key = match print_key(&reader, Some(KEY_TASKS)) {
        Ok(listing) => listing,
        Err(err) => {
            survey.unavailable = Some(format!("{KEY_TASKS} could not be resolved: {err}"));
            return survey;
        }
    };
    survey.tasks_declared = Some(tasks_key.subkeys.declared);
    survey.tasks_index_complete = tasks_key.subkeys.is_complete();
    for node in &tasks_key.subkeys.keys {
        if survey.tasks.len() >= MAX_TASKS {
            survey.capped = true;
            break;
        }
        let id = node.name.text.clone();
        let path = format!("{KEY_TASKS}\\{id}");
        match print_key(&reader, Some(&path)) {
            Ok(listing) => survey.tasks.push(read_task(id, &listing)),
            Err(err) => survey.tasks.push(ScheduledTask {
                id,
                path: TaskValue::Unavailable(err.to_string()),
                uri: TaskValue::Absent,
                author: TaskValue::Absent,
                description: TaskValue::Absent,
                date: TaskValue::Absent,
                schema: TaskValue::Absent,
                version: TaskValue::Absent,
                hash: TaskValue::Absent,
                actions: None,
                actions_error: None,
                dynamic_info: None,
                dynamic_info_error: None,
                triggers_length: None,
                triggers: None,
                triggers_error: None,
                other_values: Vec::new(),
                complete: false,
                notes: vec![format!("the task's key could not be read: {err}")],
            }),
        }
    }
    survey
}

/// Read one task's values.
fn read_task(id: String, listing: &KeyListing) -> ScheduledTask {
    let value = |name: &str| -> TaskValue {
        let Some(value) = listing
            .values
            .values
            .iter()
            .find(|v| v.name.text.eq_ignore_ascii_case(name))
        else {
            return TaskValue::Absent;
        };
        match &value.data {
            ValueData::Available { raw, decoded } => match decoded {
                RegistryData::Text(text) => TaskValue::Text(text.text.clone()),
                RegistryData::Dword(d) => TaskValue::Dword(*d),
                _ => TaskValue::Binary(raw.clone()),
            },
            ValueData::Unavailable(incomplete) => TaskValue::Unavailable(incomplete.detail.clone()),
        }
    };
    let known = [
        "Path",
        "URI",
        "Author",
        "Description",
        "Date",
        "Schema",
        "Version",
        "Hash",
        "Actions",
        "DynamicInfo",
        "Triggers",
    ];
    let other_values: Vec<String> = listing
        .values
        .values
        .iter()
        .map(|v| v.name.text.clone())
        .filter(|name| !known.iter().any(|k| k.eq_ignore_ascii_case(name)))
        .collect();

    let actions_value = value("Actions");
    let (actions, actions_error) = match &actions_value {
        TaskValue::Binary(blob) => match decode_actions(blob) {
            Ok(actions) => (Some(actions), None),
            Err(err) => (None, Some(err)),
        },
        TaskValue::Unavailable(why) => (
            None,
            Some(format!("the Actions data could not be read: {why}")),
        ),
        TaskValue::Absent => (None, Some("the key holds no Actions value".to_string())),
        _ => (None, Some("the Actions value is not binary".to_string())),
    };
    let dynamic_value = value("DynamicInfo");
    let (dynamic_info, dynamic_info_error) = match &dynamic_value {
        TaskValue::Binary(blob) => match decode_dynamic_info(blob) {
            Ok(info) => (Some(info), None),
            Err(err) => (None, Some(err)),
        },
        TaskValue::Unavailable(why) => (
            None,
            Some(format!("the DynamicInfo data could not be read: {why}")),
        ),
        TaskValue::Absent => (None, Some("the key holds no DynamicInfo value".to_string())),
        _ => (
            None,
            Some("the DynamicInfo value is not binary".to_string()),
        ),
    };
    let triggers = value("Triggers");
    let mut notes = Vec::new();
    let (decoded_triggers, triggers_error) = match &triggers {
        TaskValue::Binary(blob) => match decode_triggers(blob) {
            Ok(decoded) => (Some(decoded), None),
            Err(err) => (None, Some(err)),
        },
        TaskValue::Unavailable(why) => {
            notes.push(format!("the Triggers data could not be read: {why}"));
            (
                None,
                Some(format!("the Triggers data could not be read: {why}")),
            )
        }
        TaskValue::Absent => (None, Some("the key holds no Triggers value".to_string())),
        _ => (None, Some("the Triggers value is not binary".to_string())),
    };
    ScheduledTask {
        id,
        path: value("Path"),
        uri: value("URI"),
        author: value("Author"),
        description: value("Description"),
        date: value("Date"),
        schema: value("Schema"),
        version: value("Version"),
        hash: value("Hash"),
        actions,
        actions_error,
        dynamic_info,
        dynamic_info_error,
        triggers_length: triggers.binary().map(<[u8]>::len),
        triggers: decoded_triggers,
        triggers_error,
        other_values,
        complete: listing.is_complete(),
        notes,
    }
}
