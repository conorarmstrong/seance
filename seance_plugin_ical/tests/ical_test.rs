//! Integration tests for the iCalendar parser plugin.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::{ExecutionMode, ForensicsModule, InputCapability};
use seance_plugin_ical::ICalParser;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

const NORMAL: &[u8] = include_bytes!("fixtures/normal.ics");
const FOLDED: &[u8] = include_bytes!("fixtures/folded.ics");
const MALFORMED: &[u8] = include_bytes!("fixtures/malformed.ics");

fn file_entry(bytes: &[u8], name: &str) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.to_vec()));
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({ "name": name }),
    )
}

/// Find the single CalendarSummary record.
fn summary(out: &[Artifact]) -> &Artifact {
    out.iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("CalendarSummary"))
        .expect("summary record present")
}

/// Find a CalendarEvent record by its summary field.
fn event_by_summary<'a>(out: &'a [Artifact], want: &str) -> &'a Artifact {
    out.iter()
        .find(|a| {
            a.metadata.get("type").and_then(|v| v.as_str()) == Some("CalendarEvent")
                && a.metadata.get("summary").and_then(|v| v.as_str()) == Some(want)
        })
        .unwrap_or_else(|| panic!("event with summary {want:?} present"))
}

fn str_field<'a>(a: &'a Artifact, key: &str) -> Option<&'a str> {
    a.metadata.get(key).and_then(|v| v.as_str())
}

#[test]
fn module_metadata_is_stable() {
    let p = ICalParser::new();
    assert_eq!(p.id(), "plugin.calendar.ical_parser");
    assert_eq!(p.subscribes_to(), vec![ArtifactType::FileEntry]);
    assert_eq!(p.input_capability(), InputCapability::Stream);
    assert_eq!(p.execution_mode(), ExecutionMode::Automatic);
}

#[test]
fn normal_calendar_parses_events_and_summary() {
    let out = ICalParser::new()
        .process(&file_entry(NORMAL, "work.ics"))
        .unwrap();

    // 3 events + 1 summary.
    let events = out
        .iter()
        .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("CalendarEvent"))
        .count();
    assert_eq!(events, 3, "expected 3 events");

    let parent = out[0].parent_id;
    assert!(parent.is_some());
    for a in &out {
        assert_eq!(a.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(
            a.parent_id, parent,
            "all records share the FileEntry parent"
        );
    }

    let ev = event_by_summary(&out, "Team Sync");
    assert_eq!(str_field(ev, "dtstart"), Some("2021-07-04T15:30:00Z"));
    assert_eq!(str_field(ev, "dtend"), Some("2021-07-04T16:30:00Z"));
    assert_eq!(
        ev.metadata.get("all_day").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(str_field(ev, "location"), Some("Conference Room A"));
    assert_eq!(str_field(ev, "status"), Some("CONFIRMED"));
    assert_eq!(str_field(ev, "uid"), Some("event-001@example.com"));
    assert_eq!(str_field(ev, "created"), Some("2021-06-01T09:00:00Z"));
    assert_eq!(str_field(ev, "last_modified"), Some("2021-06-02T09:00:00Z"));
    assert_eq!(
        ev.metadata.get("sequence").and_then(|v| v.as_i64()),
        Some(0)
    );
    assert_eq!(str_field(ev, "calendar_name"), Some("Work Calendar"));

    let s = summary(&out);
    assert_eq!(str_field(s, "calendar_name"), Some("Work Calendar"));
    assert_eq!(
        s.metadata.get("event_count").and_then(|v| v.as_u64()),
        Some(3)
    );
    assert_eq!(str_field(s, "version"), Some("2.0"));
    assert_eq!(
        str_field(s, "prodid"),
        Some("-//Seance Test//Calendar 1.0//EN")
    );
}

#[test]
fn all_day_event_is_detected() {
    let out = ICalParser::new()
        .process(&file_entry(NORMAL, "work.ics"))
        .unwrap();
    let ev = event_by_summary(&out, "Company Holiday");
    assert_eq!(
        ev.metadata.get("all_day").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(str_field(ev, "dtstart"), Some("2021-07-05"));
    assert_eq!(str_field(ev, "dtend"), Some("2021-07-06"));
}

#[test]
fn recurrence_rule_is_captured() {
    let out = ICalParser::new()
        .process(&file_entry(NORMAL, "work.ics"))
        .unwrap();
    let ev = event_by_summary(&out, "Weekly Standup");
    assert_eq!(str_field(ev, "recurrence"), Some("FREQ=WEEKLY;BYDAY=MO"));
}

#[test]
fn folded_lines_unfolded_and_escaping_decoded() {
    let out = ICalParser::new()
        .process(&file_entry(FOLDED, "folded.ics"))
        .unwrap();

    // Escaped comma decoded in the summary.
    let ev = event_by_summary(&out, "Project Kickoff, Phase 1");

    // Escaped semicolon decoded in the location.
    assert_eq!(str_field(ev, "location"), Some("Building 5; Room 200"));

    // Folded continuation joined mid-word; \n decoded to real newlines.
    let desc = str_field(ev, "description").expect("description present");
    assert!(desc.contains("First line of notes."), "desc: {desc:?}");
    assert!(
        desc.contains("laptops and chargers"),
        "unfolding merged mid-word: {desc:?}"
    );
    assert_eq!(
        desc.matches('\n').count(),
        2,
        "two decoded newlines: {desc:?}"
    );
    assert!(
        !desc.contains("\\n"),
        "raw escape must be decoded: {desc:?}"
    );
}

#[test]
fn organizer_and_attendees_parsed() {
    let out = ICalParser::new()
        .process(&file_entry(FOLDED, "folded.ics"))
        .unwrap();
    let ev = event_by_summary(&out, "Project Kickoff, Phase 1");

    assert_eq!(
        str_field(ev, "organizer"),
        Some("Alice Manager <alice@example.com>")
    );

    let attendees: Vec<&str> = ev
        .metadata
        .get("attendees")
        .and_then(|v| v.as_array())
        .expect("attendees array")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        attendees,
        vec![
            "Bob Attendee <bob@example.com>",
            "Carol Guest <carol@example.com>"
        ]
    );
    assert_eq!(str_field(ev, "status"), Some("TENTATIVE"));
}

#[test]
fn calendar_name_falls_back_to_filename() {
    // folded.ics has no X-WR-CALNAME, so the source filename is used.
    let out = ICalParser::new()
        .process(&file_entry(FOLDED, "folded.ics"))
        .unwrap();
    assert_eq!(
        str_field(summary(&out), "calendar_name"),
        Some("folded.ics")
    );
    let ev = event_by_summary(&out, "Project Kickoff, Phase 1");
    assert_eq!(str_field(ev, "calendar_name"), Some("folded.ics"));
}

#[test]
fn malformed_truncated_does_not_panic() {
    // Truncated calendar (no END) must not panic — and must not vanish. The
    // content already identified this as an iCalendar, so an empty result made
    // a corrupt diary indistinguishable from a file that never held one
    // (B5-035).
    let out = ICalParser::new()
        .process(&file_entry(MALFORMED, "broken.ics"))
        .unwrap();
    assert_eq!(out.len(), 1, "{out:?}");
    let md = &out[0].metadata;
    assert_eq!(
        md.get("type").and_then(|v| v.as_str()),
        Some("CalendarParseStatus")
    );
    assert_eq!(
        md.get("status").and_then(|v| v.as_str()),
        Some("ParseFailed")
    );
    assert_eq!(md.get("content_incomplete"), Some(&json!(true)));
    assert_eq!(
        md.get("content_incomplete_reason").and_then(|v| v.as_str()),
        Some("unresolved_structure")
    );
    assert_eq!(
        md.get("file_name").and_then(|v| v.as_str()),
        Some("broken.ics")
    );
}

/// A calendar whose parse stops part-way must say so on its summary.
///
/// What an examiner learns: whether "the custodian had no appointment that day"
/// is supportable. Events after the malformed block were never read, and a
/// summary that reports only the events it reached presents a fragment as the
/// whole diary (B5-019).
#[test]
fn a_calendar_whose_parse_stopped_says_so_on_its_summary() {
    // One sound VCALENDAR followed by a truncated one: the parser keeps the
    // first and stops at the second.
    let mut bytes = NORMAL.to_vec();
    bytes.extend_from_slice(MALFORMED);

    let out = ICalParser::new()
        .process(&file_entry(&bytes, "two.ics"))
        .unwrap();

    // The sound calendar's events are still recovered.
    assert!(
        out.iter()
            .any(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("CalendarEvent")),
        "the events before the malformed block are still evidence"
    );

    let s = summary(&out);
    assert_eq!(s.metadata.get("content_incomplete"), Some(&json!(true)));
    assert_eq!(s.metadata.get("inventory_incomplete"), Some(&json!(true)));
    assert_eq!(s.metadata.get("parse_stopped"), Some(&json!(true)));
    assert!(
        str_field(s, "message").is_some_and(|m| m.contains("stopped")),
        "the summary must say what stopped it: {:?}",
        s.metadata
    );
}

#[test]
fn content_detection_is_primary_over_extension() {
    // Valid VCALENDAR content but a non-calendar extension: still parsed.
    let out = ICalParser::new()
        .process(&file_entry(NORMAL, "calendar.dat"))
        .unwrap();
    let events = out
        .iter()
        .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("CalendarEvent"))
        .count();
    assert_eq!(events, 3);
    // X-WR-CALNAME still wins for the calendar name.
    assert_eq!(
        str_field(summary(&out), "calendar_name"),
        Some("Work Calendar")
    );
}

#[test]
fn non_ics_content_yields_nothing() {
    let out = ICalParser::new()
        .process(&file_entry(
            b"just some random notes, not a calendar\n",
            "notes.txt",
        ))
        .unwrap();
    assert!(out.is_empty());
}

#[test]
fn ics_extension_with_garbage_content_yields_nothing() {
    // Extension hint alone must not fabricate records from non-calendar bytes.
    let out = ICalParser::new()
        .process(&file_entry(b"hello world, this is not ical\n", "trap.ics"))
        .unwrap();
    assert!(out.is_empty());
}

use seance_core::test_support::TruncatedSource;

/// "Could not determine" must not render as "nothing here".
///
/// The two silences above — a `.ics`-named note is not a calendar, so nothing
/// is reported — are only safe while the parser can tell them apart from a file
/// whose bytes it never got. A source that declares 4096 bytes and hands over
/// nine cannot say the file held no appointments; an empty return there is the
/// parser answering a question it did not ask the evidence (fail closed).
#[test]
fn an_ics_whose_bytes_could_not_be_read_says_so_rather_than_nothing() {
    let data: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(b"BEGIN:VCA".to_vec(), 4096));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({ "name": "unreadable.ics" }),
    );
    let out = ICalParser::new().process(&artifact).unwrap();
    assert_eq!(out.len(), 1, "{out:?}");
    let md = &out[0].metadata;
    assert_eq!(
        md.get("type").and_then(|v| v.as_str()),
        Some("CalendarParseStatus")
    );
    assert_eq!(
        md.get("status").and_then(|v| v.as_str()),
        Some("ContentUnreadable"),
        "a short read is not a calendar that failed to parse"
    );
    assert_eq!(md.get("content_incomplete"), Some(&json!(true)));
    assert_eq!(
        md.get("content_incomplete_reason").and_then(|v| v.as_str()),
        Some("short_read")
    );
    // The sentence has to land on the key the examiner-facing reader shows.
    assert!(md
        .get("content_incomplete_detail")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty()));
}

#[test]
fn directory_is_skipped() {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(NORMAL.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({ "name": "cal_dir", "is_directory": true }),
    );
    assert!(ICalParser::new().process(&artifact).unwrap().is_empty());
}

#[test]
fn missing_data_source_is_skipped() {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({ "name": "ghost.ics" }),
    );
    assert!(ICalParser::new().process(&artifact).unwrap().is_empty());
}

/// HUNT-182: the same calendar as `normal.ics`, prefixed with a UTF-8 BOM and
/// with CRLF line ends — the shape Windows Outlook's export writes. The fixture
/// is `normal.ics` with those two changes made by script; no Outlook-written
/// file is in the tree. Before the fix the probe skipped the BOM but the `ical`
/// stream did not, so the parse failed with `MissingHeader` and the file was
/// filed as `ParseFailed` with every event lost.
#[test]
fn a_utf8_bom_does_not_defeat_the_parse() {
    const BOM_CRLF: &[u8] = include_bytes!("fixtures/bom_crlf.ics");
    assert_eq!(&BOM_CRLF[..3], &[0xEF, 0xBB, 0xBF]);
    let out = ICalParser::new()
        .process(&file_entry(BOM_CRLF, "outlook.ics"))
        .unwrap();
    let statuses: Vec<_> = out
        .iter()
        .filter(|a| str_field(a, "type") == Some("CalendarParseStatus"))
        .map(|a| a.metadata.clone())
        .collect();
    assert!(statuses.is_empty(), "no parse-failure record: {statuses:?}");
    let events = out
        .iter()
        .filter(|a| str_field(a, "type") == Some("CalendarEvent"))
        .count();
    assert_eq!(events, 3, "every event of the BOM-prefixed calendar");
    let ev = event_by_summary(&out, "Team Sync");
    assert_eq!(str_field(ev, "dtstart"), Some("2021-07-04T15:30:00Z"));
}

/// The probe also admits leading whitespace before `BEGIN:VCALENDAR`; the
/// stream must skip the same prefix the probe skipped.
#[test]
fn leading_blank_lines_after_a_bom_do_not_defeat_the_parse() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF, b'\r', b'\n', b' ', b'\n'];
    bytes.extend_from_slice(NORMAL);
    let out = ICalParser::new()
        .process(&file_entry(&bytes, "padded.ics"))
        .unwrap();
    let events = out
        .iter()
        .filter(|a| str_field(a, "type") == Some("CalendarEvent"))
        .count();
    assert_eq!(
        events,
        3,
        "{:?}",
        out.iter().map(|a| &a.metadata).collect::<Vec<_>>()
    );
}

/// HUNT-210: the preamble is skipped on the stream, not inside the 512-byte
/// probe. A BOM and 600 bytes of blank, space-indented CRLF lines ahead of `normal.ics` put
/// `BEGIN:VCALENDAR` past the probe window; the calendar must still parse,
/// whether the file is admitted by its `.ics` name or by its content alone.
#[test]
fn leading_whitespace_past_the_probe_window_does_not_defeat_the_parse() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend(std::iter::repeat_n(*b" \t\r\n", 150).flatten());
    assert!(bytes.len() > 512);
    bytes.extend_from_slice(NORMAL);
    for name in ["padded.ics", "padded.dat"] {
        let out = ICalParser::new()
            .process(&file_entry(&bytes, name))
            .unwrap();
        let events = out
            .iter()
            .filter(|a| str_field(a, "type") == Some("CalendarEvent"))
            .count();
        assert_eq!(
            events,
            3,
            "{name}: {:?}",
            out.iter().map(|a| &a.metadata).collect::<Vec<_>>()
        );
    }
}

/// HUNT-216: readability is judged on the window actually parsed. With more
/// than 512 bytes of preamble the content tests read a second window from
/// where the preamble ends; a source that hands over the whole preamble and
/// then stops short (here nine bytes, then nothing, of a declared 4 KiB) must
/// be reported as unreadable, not dropped as "a `.ics` name over no calendar".
/// The second case stops exactly at the end of the preamble.
#[test]
fn a_short_read_past_a_long_preamble_says_so_rather_than_nothing() {
    let mut preamble = vec![0xEF, 0xBB, 0xBF];
    preamble.extend(std::iter::repeat_n(*b" \t\r\n", 150).flatten());
    assert!(preamble.len() > 512);
    for tail in [&b"BEGIN:VCA"[..], &b""[..]] {
        let mut readable = preamble.clone();
        readable.extend_from_slice(tail);
        let data: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(readable, 4096));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(data),
            json!({ "name": "padded.ics" }),
        );
        let out = ICalParser::new().process(&artifact).unwrap();
        assert_eq!(out.len(), 1, "tail {tail:?}: {out:?}");
        let md = &out[0].metadata;
        assert_eq!(
            md.get("status").and_then(|v| v.as_str()),
            Some("ContentUnreadable"),
            "tail {tail:?}"
        );
        assert_eq!(
            md.get("content_incomplete_reason").and_then(|v| v.as_str()),
            Some("short_read")
        );
    }
}
