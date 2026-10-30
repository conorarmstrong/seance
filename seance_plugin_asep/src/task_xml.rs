//! Scheduled Task 2.0 XML: encoding sniff, extraction, and the entry it makes.
//!
//! A task file under `\Windows\System32\Tasks` has no extension and no reliable
//! footer, so it is identified by content: the `<Task>` root plus the Task
//! Scheduler namespace. The Task Scheduler service writes these as **UTF-16LE
//! with a byte-order mark**, while tasks deployed by Group Policy or dropped by
//! hand are frequently UTF-8 and sometimes omit the XML declaration entirely.
//! Assuming one encoding is the single most common reason a task parser reports
//! a machine as having no scheduled tasks when it has hundreds, so both are
//! sniffed and neither is assumed.
//!
//! The reader here is deliberately small and defensive: no entity expansion
//! (so no XXE and no billion-laughs), a bounded element depth, a bounded event
//! count, and a bounded text length. A file that trips any bound yields a task
//! marked incomplete rather than a truncated task presented as whole, and a
//! file that will not parse at all yields an entry marked unread rather than
//! nothing at all — a scheduled task that silently disappears from the report
//! is worse than one reported as unreadable.

use crate::record::{AsepEntry, InstalledTime, LocationKind, ReadStatus};
use seance_core::io::IncompleteReason;
use serde_json::json;
use thiserror::Error;

/// The namespace that identifies a Task Scheduler 2.0 definition.
pub const TASK_NAMESPACE: &str = "schemas.microsoft.com/windows/2004/02/mit/task";

/// Bytes of a candidate file inspected for the content signature.
pub const DETECT_WINDOW: usize = 4096;

/// Maximum element nesting accepted.
const MAX_DEPTH: usize = 64;

/// Maximum markup events processed before the parse is declared incomplete.
const MAX_EVENTS: usize = 200_000;

/// Maximum triggers retained.
const MAX_TRIGGERS: usize = 512;

/// Maximum actions retained. The Task Scheduler itself allows 32.
const MAX_ACTIONS: usize = 64;

/// Maximum characters kept from any one text node.
const MAX_TEXT: usize = 8192;

/// Why a task definition could not be read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TaskParseError {
    /// The bytes are not a Task Scheduler definition.
    #[error("not a Task Scheduler definition: {0}")]
    NotATask(&'static str),
    /// The bytes could not be decoded to text under any supported encoding.
    #[error("task definition could not be decoded as UTF-16LE or UTF-8")]
    Undecodable,
    /// The markup is structurally broken.
    #[error("malformed task XML: {0}")]
    Malformed(&'static str),
    /// The document parsed but carried no `<Task>` root.
    #[error("no <Task> root element was found")]
    NoTaskElement,
}

/// One trigger from a task's `<Triggers>` block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskTrigger {
    /// The trigger element's local name, e.g. `LogonTrigger`.
    pub kind: String,
    /// `StartBoundary`, as stored.
    pub start: Option<String>,
    /// `EndBoundary`, as stored.
    pub end: Option<String>,
    /// The trigger's own `Enabled` flag.
    pub enabled: Option<bool>,
    /// `UserId`, for logon and session triggers.
    pub user: Option<String>,
}

/// One action from a task's `<Actions>` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskAction {
    /// `<Exec>`: a program and its arguments.
    Exec {
        /// `Command`, as stored (environment variables are not expanded).
        command: Option<String>,
        /// `Arguments`, as stored.
        arguments: Option<String>,
        /// `WorkingDirectory`, as stored.
        working_dir: Option<String>,
    },
    /// `<ComHandler>`: a COM class, with no command line at all.
    ComHandler {
        /// The `ClassId` the handler names.
        class_id: Option<String>,
    },
}

/// Fields gathered while an `<Exec>` element is open.
#[derive(Debug, Default)]
struct ExecAccum {
    command: Option<String>,
    arguments: Option<String>,
    working_dir: Option<String>,
}

/// Fields gathered while a `<ComHandler>` element is open.
#[derive(Debug, Default)]
struct ComAccum {
    class_id: Option<String>,
}

/// A task definition, reduced to the fields an examiner needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedTask {
    /// `RegistrationInfo/URI` — the task's path in the scheduler tree.
    pub uri: Option<String>,
    /// `RegistrationInfo/Author`.
    pub author: Option<String>,
    /// `RegistrationInfo/Description`.
    pub description: Option<String>,
    /// `RegistrationInfo/Date`, as stored.
    pub registration_date: Option<String>,
    /// `Principals/Principal/UserId` — the account the task runs as.
    pub principal_user: Option<String>,
    /// `Principals/Principal/LogonType`.
    pub logon_type: Option<String>,
    /// `Principals/Principal/RunLevel`.
    pub run_level: Option<String>,
    /// `Settings/Enabled`.
    pub enabled: Option<bool>,
    /// `Settings/Hidden`.
    pub hidden: Option<bool>,
    /// Every trigger, in document order.
    pub triggers: Vec<TaskTrigger>,
    /// Every action, in document order.
    pub actions: Vec<TaskAction>,
    /// A cap was reached; the task is reported as partially read.
    pub incomplete_reason: Option<String>,
    /// The standard classification of `incomplete_reason`, carried onto the
    /// entry so cross-plugin honesty tooling can filter on it (B3-025).
    pub incomplete_code: Option<IncompleteReason>,
}

/// Decode a task file to text, honouring the byte-order mark.
///
/// UTF-16LE with a BOM is what the Task Scheduler writes; UTF-16BE, a UTF-8
/// BOM and plain UTF-8 are all accepted too. Lossy decoding is used for UTF-16
/// so that one bad surrogate in a large file does not discard every task
/// definition in it; the substitution is confined to that character.
pub fn decode(bytes: &[u8]) -> Result<String, TaskParseError> {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => Ok(decode_utf16(rest, true)),
        [0xFE, 0xFF, rest @ ..] => Ok(decode_utf16(rest, false)),
        [0xEF, 0xBB, 0xBF, rest @ ..] => {
            String::from_utf8(rest.to_vec()).map_err(|_| TaskParseError::Undecodable)
        }
        _ => match std::str::from_utf8(bytes) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => {
                // A BOM-less UTF-16LE file has a NUL as every second byte.
                if bytes.len() >= 4 && bytes.get(1) == Some(&0) && bytes.get(3) == Some(&0) {
                    Ok(decode_utf16(bytes, true))
                } else {
                    Err(TaskParseError::Undecodable)
                }
            }
        },
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            let (a, b) = (
                c.first().copied().unwrap_or(0),
                c.get(1).copied().unwrap_or(0),
            );
            if little_endian {
                u16::from_le_bytes([a, b])
            } else {
                u16::from_be_bytes([a, b])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// Content signature for a Task Scheduler 2.0 definition.
///
/// Both the `<Task` element **and** the task namespace must be present.
/// Requiring only `<Task` would misclassify unrelated XML; requiring only the
/// namespace would match documentation and scripts that merely mention it.
pub fn looks_like_task_xml(bytes: &[u8]) -> bool {
    let window = bytes.get(..bytes.len().min(DETECT_WINDOW)).unwrap_or(bytes);
    // A fixed window can cut a multi-byte character in half, which is a decode
    // error rather than evidence the file is not a task. Fall back to a lossy
    // read of the same window so a truncation never becomes a "no tasks on this
    // machine" answer.
    let text = decode(window).unwrap_or_else(|_| String::from_utf8_lossy(window).into_owned());
    text.contains("<Task") && text.contains(TASK_NAMESPACE)
}

/// Parse a decoded task definition.
pub fn parse(text: &str) -> Result<ParsedTask, TaskParseError> {
    if !text.contains(TASK_NAMESPACE) {
        return Err(TaskParseError::NotATask(
            "the Task Scheduler namespace is absent",
        ));
    }

    let bytes = text.as_bytes();
    let mut task = ParsedTask::default();
    let mut stack: Vec<String> = Vec::new();
    let mut pending_text: Option<String> = None;
    let mut trigger: Option<TaskTrigger> = None;
    let mut action_exec: Option<ExecAccum> = None;
    let mut action_com: Option<ComAccum> = None;
    let mut saw_task_root = false;
    let mut events = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        events = events.saturating_add(1);
        if events > MAX_EVENTS {
            task.incomplete_reason = Some(format!(
                "The task definition exceeded {MAX_EVENTS} markup events and was only \
                 partially read."
            ));
            task.incomplete_code = Some(IncompleteReason::CapReached);
            break;
        }

        let Some(rel) = bytes.get(i..).and_then(|s| find_byte(s, b'<')) else {
            break;
        };
        let lt = i.saturating_add(rel);
        if rel > 0 {
            let raw = text.get(i..lt).unwrap_or("").trim();
            if !raw.is_empty() {
                pending_text = Some(decode_entities(raw));
            }
        }
        i = lt;

        match bytes.get(i.saturating_add(1)) {
            None => break,
            Some(b'?') => {
                i = skip_to(bytes, i, b"?>").ok_or(TaskParseError::Malformed(
                    "unterminated processing instruction",
                ))?;
            }
            Some(b'!') => {
                if bytes.get(i..i.saturating_add(4)) == Some(b"<!--".as_slice()) {
                    i = skip_to(bytes, i, b"-->")
                        .ok_or(TaskParseError::Malformed("unterminated comment"))?;
                } else if bytes.get(i..i.saturating_add(9)) == Some(b"<![CDATA[".as_slice()) {
                    let start = i.saturating_add(9);
                    let end = find_slice(bytes.get(start..).unwrap_or(&[]), b"]]>")
                        .ok_or(TaskParseError::Malformed("unterminated CDATA section"))?;
                    if let Some(raw) = text.get(start..start.saturating_add(end)) {
                        let trimmed = raw.trim();
                        if !trimmed.is_empty() {
                            pending_text = Some(truncate_text(trimmed));
                        }
                    }
                    i = start.saturating_add(end).saturating_add(3);
                } else {
                    // A DOCTYPE or other declaration. It is skipped rather than
                    // processed: no external entity is ever resolved.
                    i = skip_past_byte(bytes, i, b'>')
                        .ok_or(TaskParseError::Malformed("unterminated declaration"))?;
                }
            }
            Some(b'/') => {
                let start = i.saturating_add(2);
                let end = skip_past_byte(bytes, i, b'>')
                    .ok_or(TaskParseError::Malformed("unterminated end tag"))?;
                let name = local_name(text.get(start..end.saturating_sub(1)).unwrap_or("").trim());
                i = end;
                let Some(top) = stack.pop() else {
                    return Err(TaskParseError::Malformed("end tag with no open element"));
                };
                if top != name {
                    return Err(TaskParseError::Malformed("mismatched end tag"));
                }
                close_element(
                    &name,
                    &stack,
                    &mut task,
                    &mut trigger,
                    &mut action_exec,
                    &mut action_com,
                    pending_text.take(),
                );
            }
            Some(_) => {
                let start = i.saturating_add(1);
                let end = scan_tag_end(bytes, i)
                    .ok_or(TaskParseError::Malformed("unterminated start tag"))?;
                let raw = text.get(start..end.saturating_sub(1)).unwrap_or("");
                let self_closing = raw.trim_end().ends_with('/');
                let raw = raw.trim_end().trim_end_matches('/');
                let name = local_name(raw.split_whitespace().next().unwrap_or("").trim());
                i = end;
                if name.is_empty() {
                    return Err(TaskParseError::Malformed("start tag with no name"));
                }
                if name == "Task" && stack.is_empty() {
                    saw_task_root = true;
                }
                pending_text = None;
                open_element(
                    &name,
                    &stack,
                    &mut trigger,
                    &mut action_exec,
                    &mut action_com,
                );
                if self_closing {
                    close_element(
                        &name,
                        &stack,
                        &mut task,
                        &mut trigger,
                        &mut action_exec,
                        &mut action_com,
                        None,
                    );
                } else {
                    if stack.len() >= MAX_DEPTH {
                        return Err(TaskParseError::Malformed(
                            "element nesting exceeded the depth limit",
                        ));
                    }
                    stack.push(name);
                }
            }
        }
    }

    if !saw_task_root {
        return Err(TaskParseError::NoTaskElement);
    }
    if task.triggers.len() >= MAX_TRIGGERS {
        task.incomplete_reason = Some(format!(
            "The task declares at least {MAX_TRIGGERS} triggers; the surplus was not read."
        ));
        task.incomplete_code = Some(IncompleteReason::CapReached);
    }
    if task.actions.len() >= MAX_ACTIONS {
        task.incomplete_reason = Some(format!(
            "The task declares at least {MAX_ACTIONS} actions; the surplus was not read."
        ));
        task.incomplete_code = Some(IncompleteReason::CapReached);
    }
    Ok(task)
}

fn open_element(
    name: &str,
    stack: &[String],
    trigger: &mut Option<TaskTrigger>,
    action_exec: &mut Option<ExecAccum>,
    action_com: &mut Option<ComAccum>,
) {
    let parent = stack.last().map(String::as_str).unwrap_or("");
    if parent == "Triggers" {
        *trigger = Some(TaskTrigger {
            kind: name.to_string(),
            ..TaskTrigger::default()
        });
    } else if parent == "Actions" {
        match name {
            "Exec" => *action_exec = Some(ExecAccum::default()),
            "ComHandler" => *action_com = Some(ComAccum::default()),
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn close_element(
    name: &str,
    stack: &[String],
    task: &mut ParsedTask,
    trigger: &mut Option<TaskTrigger>,
    action_exec: &mut Option<ExecAccum>,
    action_com: &mut Option<ComAccum>,
    text: Option<String>,
) {
    let parent = stack.last().map(String::as_str).unwrap_or("");
    let grandparent = stack
        .len()
        .checked_sub(2)
        .and_then(|i| stack.get(i))
        .map(String::as_str)
        .unwrap_or("");

    // A completed trigger or action.
    if parent == "Triggers" {
        if let Some(t) = trigger.take() {
            if task.triggers.len() < MAX_TRIGGERS {
                task.triggers.push(t);
            }
        }
        return;
    }
    if parent == "Actions" {
        if name == "Exec" {
            if let Some(exec) = action_exec.take() {
                if task.actions.len() < MAX_ACTIONS {
                    task.actions.push(TaskAction::Exec {
                        command: exec.command,
                        arguments: exec.arguments,
                        working_dir: exec.working_dir,
                    });
                }
            }
        } else if name == "ComHandler" {
            if let Some(com) = action_com.take() {
                if task.actions.len() < MAX_ACTIONS {
                    task.actions.push(TaskAction::ComHandler {
                        class_id: com.class_id,
                    });
                }
            }
        }
        return;
    }

    let Some(text) = text else { return };
    let text = truncate_text(&text);

    // Fields inside an open Exec / ComHandler action.
    if let Some(exec) = action_exec.as_mut().filter(|_| parent == "Exec") {
        match name {
            "Command" => exec.command = Some(text),
            "Arguments" => exec.arguments = Some(text),
            "WorkingDirectory" => exec.working_dir = Some(text),
            _ => {}
        }
        return;
    }
    if let Some(com) = action_com.as_mut().filter(|_| parent == "ComHandler") {
        if name == "ClassId" {
            com.class_id = Some(text);
        }
        return;
    }

    // Fields inside an open trigger.
    if let Some(t) = trigger.as_mut().filter(|_| grandparent == "Triggers") {
        match name {
            "StartBoundary" => t.start = Some(text),
            "EndBoundary" => t.end = Some(text),
            "Enabled" => t.enabled = parse_bool(&text),
            "UserId" => t.user = Some(text),
            _ => {}
        }
        return;
    }

    match (parent, name) {
        ("RegistrationInfo", "Date") => task.registration_date = Some(text),
        ("RegistrationInfo", "Author") => task.author = Some(text),
        ("RegistrationInfo", "Description") => task.description = Some(text),
        ("RegistrationInfo", "URI") => task.uri = Some(text),
        ("Settings", "Enabled") => task.enabled = parse_bool(&text),
        ("Settings", "Hidden") => task.hidden = parse_bool(&text),
        ("Principal", "UserId") => task.principal_user = Some(text),
        ("Principal", "GroupId") => {
            if task.principal_user.is_none() {
                task.principal_user = Some(text);
            }
        }
        ("Principal", "LogonType") => task.logon_type = Some(text),
        ("Principal", "RunLevel") => task.run_level = Some(text),
        _ => {}
    }
}

fn parse_bool(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

fn truncate_text(text: &str) -> String {
    if text.chars().count() <= MAX_TEXT {
        return text.to_string();
    }
    text.chars().take(MAX_TEXT).collect()
}

fn local_name(raw: &str) -> String {
    match raw.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => raw.to_string(),
    }
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|b| *b == needle)
}

fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Index just past the next occurrence of `needle` at or after `from`.
fn skip_to(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let rest = bytes.get(from..)?;
    let pos = find_slice(rest, needle)?;
    from.checked_add(pos)?.checked_add(needle.len())
}

/// Index just past the next `needle` byte at or after `from`.
fn skip_past_byte(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    let rest = bytes.get(from..)?;
    let pos = find_byte(rest, needle)?;
    from.checked_add(pos)?.checked_add(1)
}

/// Index just past the `>` that closes a start tag, honouring quoted attribute
/// values so a `>` inside an attribute does not end the tag early.
fn scan_tag_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    let mut i = from;
    while let Some(b) = bytes.get(i) {
        match (quote, *b) {
            (None, b'"') | (None, b'\'') => quote = Some(*b),
            (Some(q), c) if c == q => quote = None,
            (None, b'>') => return i.checked_add(1),
            _ => {}
        }
        i = i.checked_add(1)?;
    }
    None
}

fn decode_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return truncate_text(raw);
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(pos) = rest.find('&') {
        out.push_str(rest.get(..pos).unwrap_or(""));
        let after = rest.get(pos..).unwrap_or("");
        let Some(semi) = after.find(';').filter(|s| *s <= 10) else {
            out.push('&');
            rest = after.get(1..).unwrap_or("");
            continue;
        };
        let entity = after.get(1..semi).unwrap_or("");
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let decoded = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse::<u32>().ok()))
                    .and_then(char::from_u32);
                match decoded {
                    Some(c) => out.push(c),
                    // An unrecognised entity is kept verbatim rather than
                    // resolved: no external entity is ever fetched or expanded.
                    None => {
                        out.push('&');
                        out.push_str(entity);
                        out.push(';');
                    }
                }
            }
        }
        rest = after.get(semi.saturating_add(1)..).unwrap_or("");
    }
    out.push_str(rest);
    truncate_text(&out)
}

// --- entry construction ------------------------------------------------------

/// A plain phrase for one trigger.
fn trigger_phrase(t: &TaskTrigger) -> String {
    let when = match t.kind.as_str() {
        "BootTrigger" => "at system boot".to_string(),
        "LogonTrigger" => match t.user.as_deref() {
            Some(user) => format!("when {user} logs on"),
            None => "when any user logs on".to_string(),
        },
        "TimeTrigger" => match t.start.as_deref() {
            Some(start) => format!("once at {start}"),
            None => "at a scheduled time".to_string(),
        },
        "CalendarTrigger" => match t.start.as_deref() {
            Some(start) => format!("on a calendar schedule beginning {start}"),
            None => "on a calendar schedule".to_string(),
        },
        "EventTrigger" => "when a matching Windows event is logged".to_string(),
        "IdleTrigger" => "when the machine becomes idle".to_string(),
        "RegistrationTrigger" => "as soon as the task is registered".to_string(),
        "SessionStateChangeTrigger" => {
            "on a session state change (connect, disconnect, lock or unlock)".to_string()
        }
        other => format!("on a {other}"),
    };
    match t.enabled {
        Some(false) => format!("{when} (this trigger is disabled)"),
        _ => when,
    }
}

/// True when the string carries an explicit UTC marker or a UTC offset.
///
/// Task times are usually local wall clock with no offset, and presenting those
/// as UTC would shift every scheduled-task event in the timeline by the
/// machine's offset. Anything without an explicit offset is therefore tagged
/// local rather than silently normalised.
fn has_explicit_offset(value: &str) -> bool {
    let t = value.trim();
    if t.ends_with('Z') || t.ends_with('z') {
        return true;
    }
    // ...T12:00:00+01:00 / -05:00
    let tail = t.get(t.len().saturating_sub(6)..).unwrap_or("");
    tail.len() == 6
        && (tail.starts_with('+') || tail.starts_with('-'))
        && tail.get(3..4) == Some(":")
}

/// Minimal shape check for an ISO 8601 date-time.
///
/// Fail-closed: a `RegistrationInfo/Date` that is not at least
/// `YYYY-MM-DDTHH:MM` is dropped rather than emitted, because a malformed value
/// promoted to a timeline event becomes a fabricated moment in the case.
fn looks_like_iso_datetime(value: &str) -> bool {
    let b = value.trim().as_bytes();
    if b.len() < 16 {
        return false;
    }
    let digits_at = |idx: usize| b.get(idx).is_some_and(u8::is_ascii_digit);
    digits_at(0)
        && digits_at(1)
        && digits_at(2)
        && digits_at(3)
        && b.get(4) == Some(&b'-')
        && digits_at(5)
        && digits_at(6)
        && b.get(7) == Some(&b'-')
        && digits_at(8)
        && digits_at(9)
        && matches!(b.get(10), Some(b'T') | Some(b't') | Some(b' '))
        && digits_at(11)
        && digits_at(12)
        && b.get(13) == Some(&b':')
        && digits_at(14)
        && digits_at(15)
}

/// Build the entry for a parsed task.
///
/// `task_path` is the file's own path on the volume, which doubles as the
/// scheduler path when the XML carries no `URI`.
pub fn task_entry(task: &ParsedTask, task_path: &str, task_name: &str) -> AsepEntry {
    let mut entry = AsepEntry::new(
        "scheduled_task",
        task.uri.clone().unwrap_or_else(|| task_name.to_string()),
        task_path,
        LocationKind::File,
    );
    entry.scope = "filesystem".to_string();
    entry.user = task.principal_user.clone();

    // The row's image is the first Exec action; every action is retained in
    // `task_actions`, so a multi-action task never loses the rest.
    let first_exec = task
        .actions
        .iter()
        .find(|a| matches!(a, TaskAction::Exec { .. }));
    if let Some(TaskAction::Exec {
        command,
        arguments,
        working_dir,
    }) = first_exec
    {
        entry.image = command.clone();
        entry.command = match (command.as_deref(), arguments.as_deref()) {
            (Some(c), Some(a)) => Some(format!("{c} {a}")),
            (Some(c), None) => Some(c.to_string()),
            _ => None,
        };
        entry.arguments = arguments.clone();
        entry.working_dir = working_dir.clone();
        entry.search_context.rule =
            crate::normalize::SearchRule::Observed(crate::normalize::ObservedLauncher::TaskExec);
    }

    let what = match (&entry.image, task.actions.first()) {
        (Some(image), _) => format!("runs {image}"),
        (None, Some(TaskAction::ComHandler { class_id })) => format!(
            "instantiates COM class {}",
            class_id.as_deref().unwrap_or("(no ClassId recorded)")
        ),
        _ => "has no action this build could read".to_string(),
    };
    let when = if task.triggers.is_empty() {
        "only when something starts it explicitly — the task defines no triggers".to_string()
    } else {
        task.triggers
            .iter()
            .map(trigger_phrase)
            .collect::<Vec<_>>()
            .join(", and ")
    };
    let as_who = match task.principal_user.as_deref() {
        Some(user) => format!(" as {user}"),
        None => String::new(),
    };
    let elevation = match task.run_level.as_deref() {
        Some("HighestAvailable") => ", with the highest privileges available to that account",
        _ => "",
    };
    entry.runs_when = format!("Windows {what}{as_who} {when}{elevation}.");

    match task.enabled {
        Some(v) => {
            entry.enabled = Some(v);
            entry.enabled_basis = format!("Settings/Enabled is {v} in the task definition.");
        }
        None => {
            entry.enabled = None;
            entry.enabled_basis =
                "The task definition carries no Settings/Enabled value, so whether it is \
                 active could not be determined."
                    .to_string();
        }
    }

    match task.registration_date.as_deref() {
        Some(date) if looks_like_iso_datetime(date) => {
            entry.installed_time = Some(InstalledTime {
                value: date.trim().to_string(),
                source: "task_registration_date",
                timezone: if has_explicit_offset(date) {
                    None
                } else {
                    Some("local")
                },
            });
        }
        Some(date) => {
            entry.installed_time_unavailable_reason = Some(
                "The task's RegistrationInfo/Date is not a well-formed date-time, so it \
                 was not used.",
            );
            entry.put("task_registration_date_raw", json!(date));
        }
        None => {
            entry.installed_time_unavailable_reason = Some(
                "The task definition carries no RegistrationInfo/Date, so when it was \
                 registered is not recorded in the task file.",
            );
        }
    }

    entry.put("task_uri", json!(task.uri));
    entry.put("task_author", json!(task.author));
    entry.put("task_description", json!(task.description));
    entry.put("task_run_level", json!(task.run_level));
    entry.put("task_logon_type", json!(task.logon_type));
    entry.put("task_hidden", json!(task.hidden));
    entry.put("task_actions_count", json!(task.actions.len()));
    entry.put(
        "task_triggers",
        json!(task
            .triggers
            .iter()
            .map(|t| json!({
                "kind": t.kind,
                "start": t.start,
                "end": t.end,
                "enabled": t.enabled,
                "user": t.user,
            }))
            .collect::<Vec<_>>()),
    );
    entry.put(
        "task_actions",
        json!(task
            .actions
            .iter()
            .map(|a| match a {
                TaskAction::Exec {
                    command,
                    arguments,
                    working_dir,
                } => json!({
                    "kind": "Exec",
                    "command": command,
                    "arguments": arguments,
                    "working_directory": working_dir,
                }),
                TaskAction::ComHandler { class_id } => json!({
                    "kind": "ComHandler",
                    "class_id": class_id,
                }),
            })
            .collect::<Vec<_>>()),
    );

    if task.hidden == Some(true) {
        entry.observe(
            "task_hidden",
            "Settings/Hidden is true, so the task is not shown in the Task Scheduler \
             interface unless hidden tasks are displayed.",
        );
    }
    if task.triggers.is_empty() {
        entry.observe(
            "no_triggers_defined",
            "The task defines no triggers, so it runs only when something starts it \
             explicitly.",
        );
    }
    if task.actions.is_empty() {
        entry.observe(
            "no_actions_read",
            "No Exec or ComHandler action was read from this definition, so what the task \
             would run is not stated here.",
        );
        entry.read_status = ReadStatus::Unread(
            "The task definition parsed but contained no action this build recognises.".to_string(),
        );
    }
    if let Some(reason) = task.incomplete_reason.clone() {
        entry.incomplete_reason = Some(reason);
        entry.incomplete_code = task.incomplete_code;
    }
    entry
}
