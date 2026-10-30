//! The `Triggers` value of a TaskCache task: when the task fires.
//!
//! # The layout, and where it comes from
//!
//! Read from the public description of the format (cyber.wtf, "Windows
//! registry analysis — today's episode: tasks", 2022) and checked against the
//! 246 `Triggers` blobs of this project's Windows 11 26200 capture, every one
//! of which decodes to its last byte. Nearly every field is *aligned*: a byte
//! or a double-word followed by padding to eight bytes, a string preceded by an
//! aligned length and padded after. The padding is relative to the field, not
//! to the blob — a WNF trigger's data is not padded, and on the capture the
//! next record follows it at an odd offset — and the padding after the blob's
//! last field may be absent.
//!
//! - A header: the version (0x15 on Windows 7, 0x16, 0x17 on Windows 10 and 11)
//!   and the earliest start and latest end across all triggers.
//! - The job bucket: flags, the CRC32 of the task's XML, the principal id
//!   (version 0x16 on) and display name (0x17 on), the user (a flag to skip
//!   it, a flag to skip the SID, the SID's type and bytes, the account name),
//!   and an optional-settings block skipped by its own length.
//! - One record per trigger, introduced by a magic: `0xDDDD` time (once, daily,
//!   weekly, monthly, monthly day-of-week), `0xFFFF` boot, `0xAAAA` logon,
//!   `0xEEEE` idle, `0x8888` registration, `0x7777` session state change,
//!   `0xCCCC` event (with its XPath subscription), `0x6666` WNF state change.
//!   Every kind but the time trigger carries the same generic body: start and
//!   end, delay, timeout, repetition interval and duration, enabled, an id.
//!
//! A time boundary carries an `isLocalized` flag. A localized boundary is the
//! wall-clock time the task was written with — what the task XML writes
//! without a zone — and is rendered without one here, never as UTC. A zero
//! FILETIME, and the all-ones "no end", are absent, never 1601.
//!
//! A trigger kind this decoder does not know stops the decode, and so does a
//! record that runs past the blob: what came before is kept, and the stop —
//! the kind or the reason, the byte it happened at, and the bytes left — is on
//! the record. Nothing is guessed.

use serde_json::{json, Value};

/// Triggers one blob may declare before the decode stops.
pub const MAX_TRIGGERS: usize = 256;
/// Longest string or buffer a blob may declare.
const MAX_FIELD_BYTES: usize = 1 << 16;
/// Value queries one event trigger may declare.
const MAX_VALUE_QUERIES: u32 = 256;
/// The versions this decoder has seen described.
const VERSIONS: std::ops::RangeInclusive<u8> = 0x15..=0x17;

/// A boundary time, kept as the blob held it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerTime {
    /// 100 ns ticks since 1601-01-01.
    pub filetime: u64,
    /// The blob's `isLocalized` flag: a wall-clock time in the machine's zone.
    pub localized: bool,
    /// RFC 3339 in UTC when not localized; the wall-clock time with no zone
    /// when localized.
    pub text: String,
}

impl TriggerTime {
    fn new(localized: bool, filetime: u64) -> Option<Self> {
        if filetime == 0 || filetime == u64::MAX {
            return None;
        }
        let rendered = seance_core::time::filetime_to_rfc3339(filetime)?;
        let text = if localized {
            rendered
                .trim_end_matches('Z')
                .trim_end_matches("+00:00")
                .to_string()
        } else {
            rendered
        };
        Some(Self {
            filetime,
            localized,
            text,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({"filetime": self.filetime, "localized": self.localized, "time": self.text})
    }
}

/// What kind of trigger, and what only that kind carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerKind {
    /// A time-based trigger. `schedule` is once, daily, weekly, monthly or
    /// monthly_dow; `data` are its three words (interval, day and month
    /// bitmaps), kept as the blob held them.
    Time {
        schedule: String,
        data: [u16; 3],
    },
    /// A WNF state change: the state name's eight bytes, and the data length.
    Wnf {
        state_name: String,
        data_length: usize,
    },
    /// A session state change (connect, disconnect, lock, unlock), for a user.
    Session {
        state_change: u32,
        user: Option<String>,
    },
    Registration,
    Logon {
        user: Option<String>,
    },
    /// An event-log subscription (an XPath query) and its value queries.
    Event {
        subscription: String,
        value_queries: Vec<(String, String)>,
    },
    Idle,
    Boot,
}

impl TriggerKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Time { .. } => "time",
            Self::Wnf { .. } => "wnf_state_change",
            Self::Session { .. } => "session_state_change",
            Self::Registration => "registration",
            Self::Logon { .. } => "logon",
            Self::Event { .. } => "event",
            Self::Idle => "idle",
            Self::Boot => "boot",
        }
    }
}

/// One trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTrigger {
    pub kind: TriggerKind,
    pub start: Option<TriggerTime>,
    pub end: Option<TriggerTime>,
    /// The delay before the task runs; not carried by a time trigger.
    pub delay_seconds: Option<u32>,
    pub repetition_interval_seconds: u32,
    pub repetition_duration_seconds: u32,
    /// A time trigger's execution time limit; `0xFFFFFFFF` is none.
    pub execution_time_limit_seconds: Option<u32>,
    pub enabled: bool,
    /// The trigger's id, on version 0x16 and later.
    pub id: Option<String>,
}

impl TaskTrigger {
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "kind": self.kind.name(),
            "start": self.start.as_ref().map(TriggerTime::to_json),
            "end": self.end.as_ref().map(TriggerTime::to_json),
            "delay_seconds": self.delay_seconds,
            "repetition_interval_seconds": self.repetition_interval_seconds,
            "repetition_interval": duration(self.repetition_interval_seconds),
            "repetition_duration_seconds": self.repetition_duration_seconds,
            "execution_time_limit_seconds": self.execution_time_limit_seconds,
            "enabled": self.enabled,
            "id": self.id,
        });
        let extra = match &self.kind {
            TriggerKind::Time { schedule, data } => {
                json!({"schedule": schedule, "schedule_data": data})
            }
            TriggerKind::Wnf {
                state_name,
                data_length,
            } => json!({"state_name": state_name, "data_length": data_length}),
            TriggerKind::Session { state_change, user } => {
                json!({"state_change": state_change, "user": user})
            }
            TriggerKind::Logon { user } => json!({"user": user}),
            TriggerKind::Event {
                subscription,
                value_queries,
            } => json!({
                "subscription": subscription,
                "value_queries": value_queries.iter().map(|(n, q)| json!({"name": n, "query": q})).collect::<Vec<_>>(),
            }),
            TriggerKind::Registration | TriggerKind::Idle | TriggerKind::Boot => json!({}),
        };
        if let (Some(out), Value::Object(extra)) = (out.as_object_mut(), extra) {
            out.extend(extra);
        }
        out
    }
}

/// An ISO 8601 duration for a count of seconds; `None` for zero.
fn duration(seconds: u32) -> Option<String> {
    if seconds == 0 {
        return None;
    }
    let (h, m, s) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    let mut out = "PT".to_string();
    if h > 0 {
        out.push_str(&format!("{h}H"));
    }
    if m > 0 {
        out.push_str(&format!("{m}M"));
    }
    if s > 0 {
        out.push_str(&format!("{s}S"));
    }
    Some(out)
}

/// A decoded `Triggers` blob.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskTriggers {
    pub version: u8,
    /// The earliest start across the triggers.
    pub start_boundary: Option<TriggerTime>,
    /// The latest end across the triggers.
    pub end_boundary: Option<TriggerTime>,
    /// The job bucket's flags.
    pub flags: u32,
    /// The CRC32 of the task's XML, as the scheduler recorded it.
    pub xml_crc32: u32,
    pub principal_id: Option<String>,
    pub display_name: Option<String>,
    /// The account the task runs as, when the bucket names one.
    pub user: Option<String>,
    pub user_sid: Option<String>,
    pub triggers: Vec<TaskTrigger>,
    /// Why the decode stopped before the blob's end, when it did.
    pub stopped: Option<String>,
}

impl TaskTriggers {
    /// Every byte of the blob decoded.
    pub fn is_whole(&self) -> bool {
        self.stopped.is_none()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "version": self.version,
            "start_boundary": self.start_boundary.as_ref().map(TriggerTime::to_json),
            "end_boundary": self.end_boundary.as_ref().map(TriggerTime::to_json),
            "flags": self.flags,
            "xml_crc32": format!("{:#010x}", self.xml_crc32),
            "principal_id": self.principal_id,
            "display_name": self.display_name,
            "user": self.user,
            "user_sid": self.user_sid,
            "triggers": self.triggers.iter().map(TaskTrigger::to_json).collect::<Vec<_>>(),
            "whole": self.is_whole(),
            "stopped": self.stopped,
        })
    }
}

/// A bounded reader over the blob.
struct Cursor<'a> {
    blob: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.blob.len())
            .ok_or_else(|| {
                format!(
                    "{what} ({n} byte(s) at byte {}) runs past the blob's {} bytes",
                    self.at,
                    self.blob.len()
                )
            })?;
        let out = &self.blob[self.at..end];
        self.at = end;
        Ok(out)
    }
    /// Padding to a multiple of eight after a field of `size` bytes. Absent
    /// padding at the blob's end is tolerated, as the capture shows it.
    fn pad(&mut self, size: usize) {
        self.at = (self.at + (8 - size % 8) % 8).min(self.blob.len());
    }
    fn u16(&mut self, what: &str) -> Result<u16, String> {
        let b = self.take(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self, what: &str) -> Result<u32, String> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self, what: &str) -> Result<u64, String> {
        let b = self.take(8, what)?;
        let mut w = [0u8; 8];
        w.copy_from_slice(b);
        Ok(u64::from_le_bytes(w))
    }
    fn aligned_u8(&mut self, what: &str) -> Result<u8, String> {
        Ok(self.take(8, what)?[0])
    }
    fn aligned_u32(&mut self, what: &str) -> Result<u32, String> {
        let b = self.take(8, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn time(&mut self, what: &str) -> Result<Option<TriggerTime>, String> {
        let localized = self.aligned_u8(what)? != 0;
        Ok(TriggerTime::new(localized, self.u64(what)?))
    }
    fn length(&mut self, n: u32, what: &str) -> Result<usize, String> {
        let n = n as usize;
        if n > MAX_FIELD_BYTES {
            return Err(format!(
                "{what} declares {n} bytes, above the {MAX_FIELD_BYTES} this decoder reads (at byte {})",
                self.at
            ));
        }
        Ok(n)
    }
    /// An aligned byte count, the UTF-16 bytes, padding.
    fn aligned_bstr(&mut self, what: &str) -> Result<String, String> {
        let raw = self.aligned_u32(what)?;
        let n = self.length(raw, what)?;
        let text = utf16(self.take(n, what)?);
        self.pad(n);
        Ok(text)
    }
    /// A four-byte byte count, the UTF-16 bytes, padding counting the length.
    fn bstr(&mut self, what: &str) -> Result<String, String> {
        let raw = self.u32(what)?;
        let n = self.length(raw, what)?;
        let text = utf16(self.take(n, what)?);
        self.pad(n + 4);
        Ok(text)
    }
    /// An aligned character count, then that many UTF-16 units and a
    /// terminator, padded; a count of zero carries no characters at all.
    fn expand_str(&mut self, what: &str) -> Result<String, String> {
        let chars = self.aligned_u32(what)?;
        if chars == 0 {
            return Ok(String::new());
        }
        let n = self.length(chars.saturating_mul(2).saturating_add(2), what)?;
        let text = utf16(self.take(n, what)?);
        self.pad(n);
        Ok(text)
    }
    fn remaining(&self) -> usize {
        self.blob.len() - self.at
    }
}

/// UTF-16LE, stopping at the first terminator.
fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// A binary SID in its string form; `None` when the bytes are not one.
fn sid_text(bytes: &[u8]) -> Option<String> {
    let (&revision, rest) = bytes.split_first()?;
    let (&count, rest) = rest.split_first()?;
    let authority = rest.get(..6)?;
    let subs = rest.get(6..6 + 4 * usize::from(count))?;
    if rest.len() != 6 + 4 * usize::from(count) {
        return None;
    }
    let authority = authority
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let mut out = format!("S-{revision}-{authority}");
    for sub in subs.as_chunks::<4>().0 {
        out.push_str(&format!("-{}", u32::from_le_bytes(*sub)));
    }
    Some(out)
}

/// The user block: (account name, SID).
fn user_info(cursor: &mut Cursor<'_>) -> Result<(Option<String>, Option<String>), String> {
    if cursor.aligned_u8("the user's skip flag")? != 0 {
        return Ok((None, None));
    }
    let mut sid = None;
    if cursor.aligned_u8("the SID's skip flag")? == 0 {
        cursor.aligned_u32("the SID's type")?;
        let raw = cursor.aligned_u32("the SID's length")?;
        let n = cursor.length(raw, "the SID")?;
        let bytes = cursor.take(n, "the SID")?;
        cursor.pad(n);
        sid = Some(sid_text(bytes).unwrap_or_else(|| {
            format!(
                "not a SID: {}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        }));
    }
    let name = cursor.aligned_bstr("the user name")?;
    Ok((Some(name), sid))
}

/// The body every trigger kind but the time trigger carries.
fn generic(cursor: &mut Cursor<'_>, version: u8, kind: TriggerKind) -> Result<TaskTrigger, String> {
    let start = cursor.time("the trigger's start")?;
    let end = cursor.time("the trigger's end")?;
    let delay = cursor.u32("the delay")?;
    let _timeout = cursor.u32("the timeout")?;
    let interval = cursor.u32("the repetition interval")?;
    let duration = cursor.u32("the repetition duration")?;
    let _duration_again = cursor.u32("the repetition duration's copy")?;
    cursor.take(4, "the stop-at-duration-end flag")?;
    let enabled = cursor.aligned_u8("the enabled flag")? != 0;
    cursor.take(8, "the trigger's unknown eight bytes")?;
    let id = if version >= 0x16 {
        Some(cursor.bstr("the trigger's id")?)
    } else {
        None
    };
    Ok(TaskTrigger {
        kind,
        start,
        end,
        delay_seconds: Some(delay),
        repetition_interval_seconds: interval,
        repetition_duration_seconds: duration,
        execution_time_limit_seconds: None,
        enabled,
        id,
    })
}

/// A time trigger's job schedule.
fn time_trigger(cursor: &mut Cursor<'_>, version: u8) -> Result<TaskTrigger, String> {
    let start = cursor.time("the schedule's start")?;
    let end = cursor.time("the schedule's end")?;
    cursor.time("the schedule's third time")?;
    let interval = cursor.u32("the repetition interval")?;
    let duration = cursor.u32("the repetition duration")?;
    let limit = cursor.u32("the execution time limit")?;
    let mode = cursor.u32("the schedule mode")?;
    let data = [
        cursor.u16("the schedule's first word")?,
        cursor.u16("the schedule's second word")?,
        cursor.u16("the schedule's third word")?,
    ];
    cursor.take(2, "padding")?;
    let flags = cursor.take(4, "the stop and enabled flags")?;
    let enabled = flags[1] != 0;
    cursor.take(12, "the schedule's tail")?;
    let id = if version >= 0x16 {
        Some(cursor.bstr("the trigger's id")?)
    } else {
        None
    };
    let schedule = match mode {
        0 => "once".to_string(),
        1 => "daily".to_string(),
        2 => "weekly".to_string(),
        3 => "monthly".to_string(),
        4 => "monthly_dow".to_string(),
        other => format!("mode {other}"),
    };
    Ok(TaskTrigger {
        kind: TriggerKind::Time { schedule, data },
        start,
        end,
        delay_seconds: None,
        repetition_interval_seconds: interval,
        repetition_duration_seconds: duration,
        execution_time_limit_seconds: (limit != u32::MAX).then_some(limit),
        enabled,
        id,
    })
}

/// One trigger record after its magic; `Ok(None)` for a magic not known.
fn record(cursor: &mut Cursor<'_>, version: u8, magic: u32) -> Result<Option<TaskTrigger>, String> {
    let trigger = match magic {
        0xDDDD => time_trigger(cursor, version)?,
        0xFFFF => generic(cursor, version, TriggerKind::Boot)?,
        0xEEEE => generic(cursor, version, TriggerKind::Idle)?,
        0x8888 => generic(cursor, version, TriggerKind::Registration)?,
        0xAAAA => {
            let mut t = generic(cursor, version, TriggerKind::Logon { user: None })?;
            let (user, _) = user_info(cursor)?;
            t.kind = TriggerKind::Logon { user };
            t
        }
        0x7777 => {
            let mut t = generic(cursor, version, TriggerKind::Registration)?;
            let state_change = cursor.aligned_u32("the session state change")?;
            let (user, _) = user_info(cursor)?;
            t.kind = TriggerKind::Session { state_change, user };
            t
        }
        0xCCCC => {
            let mut t = generic(cursor, version, TriggerKind::Registration)?;
            let subscription = cursor.expand_str("the event subscription")?;
            cursor.take(8, "the event trigger's two unknown words")?;
            cursor.expand_str("the event trigger's unknown string")?;
            let count = cursor.aligned_u32("the value-query count")?;
            if count > MAX_VALUE_QUERIES {
                return Err(format!(
                    "the event trigger declares {count} value queries, above the \
                     {MAX_VALUE_QUERIES} this decoder reads"
                ));
            }
            let mut value_queries = Vec::new();
            for _ in 0..count {
                let name = cursor.expand_str("a value query's name")?;
                let query = cursor.expand_str("a value query")?;
                value_queries.push((name, query));
            }
            t.kind = TriggerKind::Event {
                subscription,
                value_queries,
            };
            t
        }
        0x6666 => {
            let mut t = generic(cursor, version, TriggerKind::Registration)?;
            let state_name: String = cursor
                .take(8, "the WNF state name")?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let raw = cursor.aligned_u32("the WNF data length")?;
            let data_length = cursor.length(raw, "the WNF data")?;
            // Not padded: the next record follows the data directly.
            cursor.take(data_length, "the WNF data")?;
            t.kind = TriggerKind::Wnf {
                state_name,
                data_length,
            };
            t
        }
        _ => return Ok(None),
    };
    Ok(Some(trigger))
}

/// Decode one `Triggers` blob.
///
/// # Errors
///
/// When the header or the job bucket runs past the blob, declares an
/// over-long field, or carries a version outside 0x15..=0x17. A trigger
/// record that fails is not an error: the decode stops there and says so.
pub fn decode_triggers(blob: &[u8]) -> Result<TaskTriggers, String> {
    let mut cursor = Cursor { blob, at: 0 };
    let version = cursor.aligned_u8("the version")?;
    if !VERSIONS.contains(&version) {
        return Err(format!(
            "Triggers version {version:#04x} is not one this decoder has seen described \
             (0x15 to 0x17); {} byte(s) not decoded",
            blob.len()
        ));
    }
    let mut out = TaskTriggers {
        version,
        start_boundary: cursor.time("the header's start")?,
        end_boundary: cursor.time("the header's end")?,
        flags: cursor.aligned_u32("the job bucket's flags")?,
        xml_crc32: cursor.aligned_u32("the XML's CRC32")?,
        ..TaskTriggers::default()
    };
    if version >= 0x16 {
        out.principal_id = Some(cursor.aligned_bstr("the principal id")?);
    }
    if version >= 0x17 {
        out.display_name = Some(cursor.aligned_bstr("the display name")?);
    }
    let (user, sid) = user_info(&mut cursor)?;
    out.user = user;
    out.user_sid = sid;
    let raw = cursor.aligned_u32("the optional settings' length")?;
    let settings = cursor.length(raw, "the optional settings")?;
    cursor.take(settings, "the optional settings")?;
    cursor.pad(settings);

    while cursor.remaining() > 0 {
        if out.triggers.len() >= MAX_TRIGGERS {
            out.stopped = Some(format!(
                "{MAX_TRIGGERS} triggers read, the most this decoder reads; {} byte(s) from \
                 byte {} not decoded",
                cursor.remaining(),
                cursor.at
            ));
            break;
        }
        let at = cursor.at;
        let left = cursor.remaining();
        let result = cursor
            .aligned_u32("a trigger's magic")
            .and_then(|magic| record(&mut cursor, version, magic).map(|t| (magic, t)));
        match result {
            Ok((_, Some(trigger))) => out.triggers.push(trigger),
            Ok((magic, None)) => {
                out.stopped = Some(format!(
                    "a trigger kind this decoder does not know ({magic:#06x}) at byte {at}; \
                     {left} byte(s) not decoded"
                ));
                break;
            }
            Err(err) => {
                out.stopped = Some(format!(
                    "the trigger record at byte {at} was refused: {err}; {left} byte(s) not \
                     decoded"
                ));
                break;
            }
        }
    }
    Ok(out)
}
