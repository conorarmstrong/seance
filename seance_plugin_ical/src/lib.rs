#![forbid(unsafe_code)]
//! iCalendar (`.ics`) parser module.
//!
//! [`ICalParser`] inspects every [`FileEntry`](ArtifactType::FileEntry) that enters
//! the pipeline, self-selects calendar files by **content** (the stream must begin
//! with `BEGIN:VCALENDAR`, ignoring a leading BOM / whitespace) with the `.ics` /
//! `.ical` / `.ifb` extension as a secondary hint, and parses the RFC 5545 stream
//! with the pure-Rust `ical` crate (which performs line unfolding and parameter
//! parsing). For each `VEVENT` it emits one `CalendarEvent`
//! [`ParsedRecord`](ArtifactType::ParsedRecord) child whose `parent_id` is the
//! source file, plus one `CalendarSummary` record describing the calendar, giving
//! the UI a dedicated event viewer surface.
//!
//! # Timestamps
//!
//! `DATE-TIME` values ending in `Z` are reformatted to RFC 3339 UTC
//! (`2021-07-04T15:30:00Z`). Floating date-times (no zone) are reformatted without
//! an offset and are not fabricated into UTC. When a `TZID` parameter is present the
//! named zone is surfaced verbatim in a `dtstart_tzid` / `dtend_tzid` key rather than
//! guessed. `DATE` values (`YYYYMMDD`) reformat to `YYYY-MM-DD` and set `all_day`.
//! Unrecognised value shapes are emitted raw.
//!
//! # Honesty & robustness
//!
//! Absent properties are omitted, never fabricated. Text escaping (`\n`, `\,`, `\;`,
//! `\\`) is decoded. Corrupt, truncated, or non-UTF-8 input never panics and never
//! fails the pipeline: whatever fully parsed is emitted, otherwise `Ok(vec![])`.
//!
//! # Registration
//!
//! Add the dependency to the integrating crate's `Cargo.toml`:
//!
//! ```toml
//! seance_plugin_ical = { path = "../seance_plugin_ical" }
//! ```
//!
//! and register with the orchestrator like any other automatic module:
//!
//! ```rust,ignore
//! orchestrator.register_module(std::sync::Arc::new(seance_plugin_ical::ICalParser::new()));
//! ```

use ical::property::Property;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, SourceCursor},
    io::{read_full, IncompleteReason},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value as JsonValue};
use std::io::{BufReader, Seek, SeekFrom};
use tracing::debug;

/// Parses iCalendar (`.ics`) files into per-event records plus a calendar summary.
pub struct ICalParser;

impl ICalParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ICalParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for ICalParser {
    fn id(&self) -> &str {
        "plugin.calendar.ical_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Directories have no content.
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }

        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Self-select by content first; extension is only a secondary hint.
        // Read the probe window with the looping read: a windowed or chunked
        // source can answer a 512-byte request with a handful of bytes, and a
        // single-shot probe would then decide a real calendar was not one.
        let mut head_buf = [0u8; 512];
        let n = read_full(data.as_ref(), 0, &mut head_buf);
        // The preamble (BOM, leading whitespace) is measured on the stream,
        // not inside the probe window: a file with more than 512 bytes of it
        // would otherwise be judged — and parsed — from whitespace alone
        // (HUNT-210). When it runs past the window, the content tests read a
        // fresh window from where the preamble ends.
        let preamble = stream_preamble_len(data.as_ref(), &head_buf[..n]);
        let mut after_buf = [0u8; 512];
        // `window_start` is where the window the content tests judge begins:
        // offset 0, or the end of a preamble that ran past the probe window.
        let (head, window_start): (&[u8], u64) = if preamble >= n && n == head_buf.len() {
            let m = read_full(data.as_ref(), preamble as u64, &mut after_buf);
            (&after_buf[..m], preamble as u64)
        } else {
            (&head_buf[..n], 0)
        };
        let content_says_calendar = content_is_ical(head);
        if !content_says_calendar && !has_ical_extension(name) {
            return Ok(Vec::new());
        }
        // Weaker than `content_is_ical`, which requires the marker at the very
        // start: enough to say the bytes really are calendar data even when
        // something precedes them (a carved fragment, a mail part).
        let head_holds_calendar_marker = content_says_calendar || holds_vcalendar_marker(head);
        // The probe asked for every byte the file declares, up to the window,
        // and the evidence did not hand them over. Whether these bytes hold a
        // calendar is therefore UNKNOWN, not answered "no" — so this is kept
        // apart from the marker test below. A partial answer is as unknown as
        // no answer: seven bytes of a declared four kilobytes cannot say a
        // calendar is absent, and testing only for `n == 0` would let the far
        // commoner short read fall through to the same silence as a note that
        // merely happens to be named `.ics` (fail closed).
        //
        // Judged on the window actually tested, not on the offset-0 probe: a
        // file whose preamble ran past the probe window is read again from
        // where it ends, and a short read of that second window is as unknown
        // as a short read of the first (HUNT-216).
        let window_expected = data
            .size()
            .saturating_sub(window_start)
            .min(head_buf.len() as u64);
        let head_unreadable = (head.len() as u64) < window_expected;

        debug!("ICalParser inspecting artifact ID: {}", artifact.id);

        // Stream through a seekable cursor; the ical crate unfolds lines itself.
        // It starts past the preamble the probe skipped — a UTF-8 BOM (Windows
        // Outlook writes one) and leading whitespace — because the `ical` crate
        // skips neither: a BOM fails the parse with `MissingHeader` and a blank
        // first line with "Missing property name" (HUNT-182).
        let mut cursor = SourceCursor::new(data.clone());
        if preamble > 0 {
            cursor
                .seek(SeekFrom::Start(preamble as u64))
                .map_err(|e| ModuleError::ParsingError(format!("seek past BOM: {e}")))?;
        }
        let reader = BufReader::new(cursor);

        // Collect every fully-parsed VCALENDAR. A parse error (corrupt /
        // truncated block) stops iteration but keeps whatever completed before
        // it — and is recorded, because the events after it were never read and
        // an unmarked partial calendar reads as the custodian's whole diary
        // (B5-019).
        let mut calendars = Vec::new();
        let mut parse_stopped: Option<String> = None;
        for cal in ical::IcalParser::new(reader) {
            match cal {
                Ok(c) => calendars.push(c),
                Err(e) => {
                    parse_stopped = Some(e.to_string());
                    break;
                }
            }
        }

        if calendars.is_empty() {
            // Nothing here is calendar data — we got in on the filename alone,
            // and the bytes hold no VCALENDAR marker at all. A status record
            // would invent an unreadable diary for every `.ics`-named file that
            // is really a note, a stub or a placeholder, and a warning that
            // fires on ordinary files is a warning an examiner learns to skip.
            // The parser is only entitled to report on calendars.
            if !head_holds_calendar_marker && !head_unreadable {
                debug!("ICalParser: {name} carries a calendar extension but no VCALENDAR marker");
                return Ok(Vec::new());
            }
            // The content already said this is a calendar — or would not be
            // read at all. An empty return makes a corrupt, truncated or
            // unreadable ICS indistinguishable from a file that never held
            // appointments (B5-035).
            let mut status: Map<String, JsonValue> = Map::new();
            status.insert("type".into(), json!("CalendarParseStatus"));
            status.insert("subtype".into(), json!("ical_not_parsed"));
            status.insert(
                "status".into(),
                json!(if head_unreadable {
                    "ContentUnreadable"
                } else if parse_stopped.is_some() {
                    "ParseFailed"
                } else {
                    "NoCalendarBlock"
                }),
            );
            status.insert("content_incomplete".into(), json!(true));
            status.insert(
                "content_incomplete_reason".into(),
                json!(if head_unreadable {
                    IncompleteReason::ShortRead.as_str()
                } else {
                    IncompleteReason::UnresolvedStructure.as_str()
                }),
            );
            status.insert("file_name".into(), json!(name));
            if let Some(ref err) = parse_stopped {
                status.insert("error".into(), json!(err));
            }
            let message = if head_unreadable {
                // Deliberately does not say the file held nothing. It says the
                // evidence would not answer, which is a different finding and
                // has a different follow-up (re-acquire, not "no appointments").
                "This file is named as an iCalendar and the evidence delivered fewer bytes \
                 than it declares, so whether it held appointments could not be determined"
            } else {
                "The file was identified as an iCalendar and not one VCALENDAR block could \
                 be parsed; no events were extracted"
            };
            status.insert("message".into(), json!(message));
            // The key the examiner-facing reader shows beside the flag
            // (`frontend/src/lib/incompleteness.ts` keys the sentence off
            // `<flag>_detail`); without it they meet the machine token alone.
            status.insert("content_incomplete_detail".into(), json!(message));
            status.insert("name".into(), json!(format!("Calendar not parsed: {name}")));
            return Ok(vec![Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                JsonValue::Object(status),
            )
            .with_parent(artifact.id)]);
        }

        // Calendar name: X-WR-CALNAME, else the source filename.
        let cal_name: Option<String> = calendars
            .iter()
            .find_map(|c| get_value(&c.properties, "X-WR-CALNAME"))
            .map(|v| decode_text(&v))
            .or_else(|| {
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                }
            });

        let mut out: Vec<Artifact> = Vec::new();
        for cal in &calendars {
            for event in &cal.events {
                let record = build_event_record(&event.properties, cal_name.as_deref());
                out.push(
                    Artifact::new(
                        artifact.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        JsonValue::Object(record),
                    )
                    .with_parent(artifact.id),
                );
            }
        }

        // One summary record for the calendar.
        let mut summary: Map<String, JsonValue> = Map::new();
        summary.insert("type".into(), json!("CalendarSummary"));
        if let Some(ref cn) = cal_name {
            summary.insert("calendar_name".into(), json!(cn));
        }
        summary.insert("event_count".into(), json!(out.len()));
        // A calendar whose parse stopped part-way holds more events than this
        // count. Saying so is the difference between "the custodian had no
        // appointment that day" and "we did not read that far" (B5-019).
        if let Some(ref err) = parse_stopped {
            summary.insert("content_incomplete".into(), json!(true));
            summary.insert(
                "content_incomplete_reason".into(),
                json!(IncompleteReason::UnresolvedStructure.as_str()),
            );
            summary.insert("inventory_incomplete".into(), json!(true));
            // A flag with no reason beside it reaches the examiner as
            // "incomplete, we were not told why". The event list is short for
            // exactly the same reason the content is partial.
            summary.insert(
                "inventory_incomplete_reason".into(),
                json!(IncompleteReason::UnresolvedStructure.as_str()),
            );
            summary.insert("parse_stopped".into(), json!(true));
            summary.insert("parse_error".into(), json!(err));
            let message = format!(
                "Parsing stopped at a malformed VCALENDAR block; events after it were not \
                 read: {err}"
            );
            summary.insert("message".into(), json!(message));
            // The keys the examiner-facing reader shows the sentence from.
            summary.insert("content_incomplete_detail".into(), json!(message));
            summary.insert("inventory_incomplete_detail".into(), json!(message));
        }
        if let Some(p) = calendars
            .iter()
            .find_map(|c| get_value(&c.properties, "PRODID"))
        {
            summary.insert("prodid".into(), json!(p));
        }
        if let Some(v) = calendars
            .iter()
            .find_map(|c| get_value(&c.properties, "VERSION"))
        {
            summary.insert("version".into(), json!(v));
        }
        out.push(
            Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                JsonValue::Object(summary),
            )
            .with_parent(artifact.id),
        );

        Ok(out)
    }
}

/// Builds a `CalendarEvent` metadata record from a VEVENT's properties.
fn build_event_record(props: &[Property], cal_name: Option<&str>) -> Map<String, JsonValue> {
    let mut record: Map<String, JsonValue> = Map::new();
    record.insert("type".into(), json!("CalendarEvent"));

    if let Some(v) = get_value(props, "SUMMARY") {
        record.insert("summary".into(), json!(decode_text(&v)));
    }
    if let Some(v) = get_value(props, "DESCRIPTION") {
        record.insert("description".into(), json!(decode_text(&v)));
    }
    if let Some(v) = get_value(props, "LOCATION") {
        record.insert("location".into(), json!(decode_text(&v)));
    }

    // DTSTART drives the all_day flag.
    let mut all_day = false;
    if let Some(p) = get_first(props, "DTSTART") {
        if let Some(raw) = p.value.as_deref() {
            let value_is_date = param(p, "VALUE")
                .map(|v| v.eq_ignore_ascii_case("DATE"))
                .unwrap_or(false);
            let (formatted, date_only) = format_datetime(raw);
            all_day = value_is_date || date_only;
            record.insert("dtstart".into(), json!(formatted));
            if let Some(tz) = param(p, "TZID") {
                record.insert("dtstart_tzid".into(), json!(tz));
            }
        }
    }
    record.insert("all_day".into(), json!(all_day));

    if let Some(p) = get_first(props, "DTEND") {
        if let Some(raw) = p.value.as_deref() {
            let (formatted, _) = format_datetime(raw);
            record.insert("dtend".into(), json!(formatted));
            if let Some(tz) = param(p, "TZID") {
                record.insert("dtend_tzid".into(), json!(tz));
            }
        }
    }

    if let Some(p) = get_first(props, "ORGANIZER") {
        if let Some(org) = format_cal_address(p) {
            record.insert("organizer".into(), json!(org));
        }
    }

    let attendees: Vec<JsonValue> = props
        .iter()
        .filter(|p| p.name.eq_ignore_ascii_case("ATTENDEE"))
        .filter_map(format_cal_address)
        .map(|s| json!(s))
        .collect();
    if !attendees.is_empty() {
        record.insert("attendees".into(), json!(attendees));
    }

    if let Some(v) = get_value(props, "STATUS") {
        record.insert("status".into(), json!(v));
    }
    if let Some(v) = get_value(props, "UID") {
        record.insert("uid".into(), json!(v));
    }
    if let Some(v) = get_value(props, "RRULE") {
        record.insert("recurrence".into(), json!(v));
    }
    if let Some(v) = get_value(props, "CREATED") {
        let (f, _) = format_datetime(&v);
        record.insert("created".into(), json!(f));
    }
    if let Some(v) = get_value(props, "LAST-MODIFIED") {
        let (f, _) = format_datetime(&v);
        record.insert("last_modified".into(), json!(f));
    }
    if let Some(v) = get_value(props, "SEQUENCE") {
        match v.parse::<i64>() {
            Ok(seq) => record.insert("sequence".into(), json!(seq)),
            Err(_) => record.insert("sequence".into(), json!(v)),
        };
    }

    if let Some(cn) = cal_name {
        record.insert("calendar_name".into(), json!(cn));
    }

    record
}

/// Length of the preamble ahead of the first calendar line: an optional UTF-8
/// BOM, then leading ASCII whitespace. The probe and the parse stream both
/// start after it, so what admits a file and what reads it cannot disagree.
fn ical_preamble_len(head: &[u8]) -> usize {
    let bom = if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        3
    } else {
        0
    };
    let ws = head[bom..]
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(head.len() - bom);
    bom + ws
}

/// Length of the preamble measured on the stream itself. When the probe
/// window `head` is preamble from end to end, the whitespace run is followed
/// through the source in 64 KiB reads until the first other byte or the end
/// of what can be read (HUNT-210).
fn stream_preamble_len(data: &dyn DataSource, head: &[u8]) -> usize {
    let mut len = ical_preamble_len(head);
    if len < head.len() || head.len() < 512 {
        return len;
    }
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let got = read_full(data, len as u64, &mut chunk);
        let ws = chunk[..got]
            .iter()
            .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .unwrap_or(got);
        len += ws;
        if ws < got || got < chunk.len() {
            return len;
        }
    }
}

/// True if the head of the stream begins with `BEGIN:VCALENDAR` after an optional
/// UTF-8 BOM and leading ASCII whitespace.
fn content_is_ical(head: &[u8]) -> bool {
    let s = &head[ical_preamble_len(head)..];
    const NEEDLE: &[u8] = b"BEGIN:VCALENDAR";
    s.len() >= NEEDLE.len() && s[..NEEDLE.len()].eq_ignore_ascii_case(NEEDLE)
}

/// Whether `BEGIN:VCALENDAR` appears anywhere in the probe window.
///
/// [`content_is_ical`] requires it at the very start, which is what admits a
/// file for parsing. This is the looser question — "are these bytes calendar
/// data at all?" — and it decides whether a file that produced no event is
/// worth reporting on. A `.ics` name over bytes with no marker anywhere is not
/// a calendar this parser failed to read; it is not a calendar.
fn holds_vcalendar_marker(head: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"BEGIN:VCALENDAR";
    head.windows(NEEDLE.len())
        .any(|w| w.eq_ignore_ascii_case(NEEDLE))
}

/// Secondary filename hint.
fn has_ical_extension(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".ics") || n.ends_with(".ical") || n.ends_with(".ifb")
}

/// First property with a case-insensitive name match.
fn get_first<'a>(props: &'a [Property], name: &str) -> Option<&'a Property> {
    props.iter().find(|p| p.name.eq_ignore_ascii_case(name))
}

/// Trimmed, non-empty value of the first matching property.
fn get_value(props: &[Property], name: &str) -> Option<String> {
    let v = get_first(props, name)?.value.as_deref()?.trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// First value of a property parameter (case-insensitive key).
fn param<'a>(p: &'a Property, key: &str) -> Option<&'a str> {
    p.params
        .as_ref()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, vals)| vals.first())
        .map(|s| s.as_str())
}

/// Formats a CAL-ADDRESS property (`ORGANIZER` / `ATTENDEE`) as `CN <email>` or,
/// when no common name is present, the bare address with any `mailto:` stripped.
fn format_cal_address(p: &Property) -> Option<String> {
    let val = p.value.as_deref()?.trim();
    let addr = if val.len() >= 7 && val[..7].eq_ignore_ascii_case("mailto:") {
        val[7..].trim()
    } else {
        val
    };
    match param(p, "CN").map(decode_text) {
        Some(cn) if !cn.is_empty() => Some(format!("{} <{}>", cn, addr)),
        _ if addr.is_empty() => None,
        _ => Some(addr.to_string()),
    }
}

/// Decodes RFC 5545 TEXT escaping: `\n`/`\N` -> newline, `\,` -> `,`, `\;` -> `;`,
/// `\\` -> `\`. Unknown escapes drop the backslash and keep the following char.
fn decode_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') | Some('N') => out.push('\n'),
                Some(',') => out.push(','),
                Some(';') => out.push(';'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Reformats an iCalendar DATE / DATE-TIME value.
///
/// Returns `(formatted, is_date_only)`. `DATE` (`YYYYMMDD`) -> `YYYY-MM-DD` with the
/// flag set; `DATE-TIME` (`YYYYMMDDTHHMMSS[Z]`) -> `YYYY-MM-DDTHH:MM:SS[Z]`.
/// Anything else is returned unchanged with the flag clear.
fn format_datetime(value: &str) -> (String, bool) {
    let v = value.trim();

    // DATE: 8 digits.
    if v.len() == 8 && v.bytes().all(|b| b.is_ascii_digit()) {
        return (format!("{}-{}-{}", &v[0..4], &v[4..6], &v[6..8]), true);
    }

    // DATE-TIME: optional trailing Z (UTC), then YYYYMMDDTHHMMSS.
    let (body, utc) = match v.strip_suffix(['Z', 'z']) {
        Some(stripped) => (stripped, true),
        None => (v, false),
    };
    if body.len() == 15
        && body.as_bytes()[8] == b'T'
        && body[..8].bytes().all(|b| b.is_ascii_digit())
        && body[9..].bytes().all(|b| b.is_ascii_digit())
    {
        let d = &body[..8];
        let t = &body[9..15];
        let formatted = format!(
            "{}-{}-{}T{}:{}:{}{}",
            &d[0..4],
            &d[4..6],
            &d[6..8],
            &t[0..2],
            &t[2..4],
            &t[4..6],
            if utc { "Z" } else { "" }
        );
        return (formatted, false);
    }

    (v.to_string(), false)
}
