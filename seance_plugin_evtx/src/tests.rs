use super::*;
use seance_core::data_source::DataSource;
use std::sync::Arc;
use uuid::Uuid;

/// Mock data source for testing
#[derive(Debug)]
pub(super) struct MockEvtxSource {
    data: Vec<u8>,
}

impl MockEvtxSource {
    pub(super) fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for MockEvtxSource {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }

        let to_read = std::cmp::min(buffer.len(), self.data.len() - offset);
        buffer[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Regression for whole-second truncation of Windows event times.
///
/// What an examiner learns: the instant an event was written, to the 100 ns
/// FILETIME resolution Windows records. A wrong answer collapses every event
/// inside a second onto one identical time, so a logon, the process it
/// spawned and a service install become unorderable against each other and
/// against the prefetch/MFT/registry times they must be correlated with.
#[test]
fn record_times_keeps_the_filetime_sub_second_remainder() {
    use chrono::TimeZone;

    // 2021-01-01T00:00:00.123456700Z: a FILETIME lands on 100 ns boundaries.
    let ts = chrono::Utc
        .timestamp_opt(1_609_459_200, 123_456_700)
        .single()
        .expect("valid instant");
    let (secs, nanos, rfc3339) = record_times(ts);

    assert_eq!(secs, 1_609_459_200, "whole seconds are unchanged");
    assert_eq!(
        nanos, 123_456_700,
        "the sub-second remainder must survive; 0 here means it was truncated"
    );
    let round_tripped =
        chrono::DateTime::parse_from_rfc3339(&rfc3339).expect("RFC 3339 must round trip");
    assert_eq!(round_tripped.timestamp(), secs);
    assert_eq!(
        round_tripped.timestamp_subsec_nanos(),
        123_456_700,
        "the string form the timeline stores must carry the remainder too"
    );
}

#[test]
fn test_parse_event_xml_security_logon() {
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" />
            <EventID>4624</EventID>
            <EventRecordID>12345</EventRecordID>
            <Computer>WORKSTATION01</Computer>
            <Channel>Security</Channel>
            <Level>4</Level>
            <Task>12544</Task>
            <Keywords>0x8020000000000000</Keywords>
            <Security UserID="S-1-5-18" />
        </System>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();

    assert_eq!(metadata.event_id, Some(4624));
    assert_eq!(metadata.event_record_id, Some(12345));
    assert_eq!(metadata.computer_name, "WORKSTATION01");
    assert_eq!(
        metadata.provider_name,
        "Microsoft-Windows-Security-Auditing"
    );
    assert_eq!(metadata.channel, "Security");
    assert_eq!(metadata.level, Some(4));
    assert_eq!(metadata.task, Some(12544));
    assert_eq!(metadata.user_sid, Some("S-1-5-18".to_string()));
}

#[test]
fn test_parse_event_xml_extracts_event_data() {
    // BUG-064: EventData/Data payload must be extracted, not dropped. This is a
    // 4688 (process creation) with named Data fields and one positional Data.
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" />
            <EventID>4688</EventID>
            <EventRecordID>42</EventRecordID>
            <Computer>WORKSTATION01</Computer>
            <Channel>Security</Channel>
        </System>
        <EventData>
            <Data Name="SubjectUserName">alice</Data>
            <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
            <Data Name="CommandLine">cmd.exe /c whoami</Data>
            <Data>positional-value</Data>
        </EventData>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();

    assert_eq!(metadata.event_id, Some(4688));
    assert_eq!(
        metadata
            .event_data
            .get("SubjectUserName")
            .and_then(|v| v.as_str()),
        Some("alice")
    );
    assert_eq!(
        metadata
            .event_data
            .get("NewProcessName")
            .and_then(|v| v.as_str()),
        Some("C:\\Windows\\System32\\cmd.exe")
    );
    assert_eq!(
        metadata
            .event_data
            .get("CommandLine")
            .and_then(|v| v.as_str()),
        Some("cmd.exe /c whoami")
    );
    // Positional (unnamed) Data is keyed by index, not lost.
    assert_eq!(
        metadata.event_data.get("Data1").and_then(|v| v.as_str()),
        Some("positional-value")
    );
}

#[test]
fn test_parse_event_xml_extracts_user_data() {
    // BUG-064: UserData leaf elements must be captured too.
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-DNS-Client" />
            <EventID>1014</EventID>
            <EventRecordID>7</EventRecordID>
            <Computer>HOST</Computer>
            <Channel>System</Channel>
        </System>
        <UserData>
            <EventXML xmlns="http://schemas.microsoft.com/vendor">
                <QueryName>example.com</QueryName>
                <AddressLength>4</AddressLength>
            </EventXML>
        </UserData>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();

    assert_eq!(metadata.event_id, Some(1014));
    assert_eq!(
        metadata
            .event_data
            .get("QueryName")
            .and_then(|v| v.as_str()),
        Some("example.com")
    );
    assert_eq!(
        metadata
            .event_data
            .get("AddressLength")
            .and_then(|v| v.as_str()),
        Some("4")
    );
}

#[test]
fn test_parse_event_xml_duplicate_data_names_not_lost() {
    // Repeated Data names must be suffixed, never silently overwritten.
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="P" />
            <EventID>1</EventID>
            <EventRecordID>1</EventRecordID>
            <Computer>C</Computer>
            <Channel>Application</Channel>
        </System>
        <EventData>
            <Data Name="Item">first</Data>
            <Data Name="Item">second</Data>
        </EventData>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();
    assert_eq!(
        metadata.event_data.get("Item").and_then(|v| v.as_str()),
        Some("first")
    );
    assert_eq!(
        metadata.event_data.get("Item_2").and_then(|v| v.as_str()),
        Some("second")
    );
}

#[test]
fn test_parse_event_xml_system_boot() {
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Kernel-General" />
            <EventID>12</EventID>
            <EventRecordID>6789</EventRecordID>
            <Computer>SERVER01</Computer>
            <Channel>System</Channel>
            <Level>4</Level>
        </System>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();

    assert_eq!(metadata.event_id, Some(12));
    assert_eq!(metadata.computer_name, "SERVER01");
    assert_eq!(metadata.channel, "System");
    assert_eq!(metadata.provider_name, "Microsoft-Windows-Kernel-General");
}

#[test]
fn test_parse_event_xml_minimal() {
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="TestProvider" />
            <EventID>100</EventID>
            <EventRecordID>1</EventRecordID>
            <Computer>TEST-PC</Computer>
            <Channel>Application</Channel>
        </System>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();

    assert_eq!(metadata.event_id, Some(100));
    assert_eq!(metadata.level, None);
    assert_eq!(metadata.task, None);
    assert_eq!(metadata.user_sid, None);
}

#[test]
fn test_parse_event_xml_invalid() {
    let invalid_xml = "not valid xml at all";
    let result = EvtxParser::parse_event_xml(invalid_xml);
    // The parser is forgiving and will not error out on invalid XML. This is by
    // design: a malformed record still says an event was written, and erroring
    // would drop it from the case entirely.
    assert!(result.is_ok());
    let metadata = result.unwrap();
    // Nothing was read, so nothing is claimed. This assertion used to read
    // `event_id == 0` -- the parser's default -- which put a Windows event ID
    // the record never carried onto the record (B8-047). 0 is a real event ID,
    // so the invented value was indistinguishable from a genuine one.
    assert_eq!(
        metadata.event_id, None,
        "an EventID that was never read is unknown, not event 0: 0 is a real ID"
    );
    assert_eq!(metadata.event_record_id, None);
    // The element was absent, not unparsable: there is no raw text to keep, and
    // that difference is itself a fact about the record.
    assert_eq!(metadata.event_id_raw, None);
    assert_eq!(metadata.event_record_id_raw, None);
    // Kept from the original test: a malformed record still parses, and the
    // string fields still fall back to their existing "Unknown" placeholder.
    assert_eq!(metadata.computer_name, "Unknown");
}

/// Regression for B8-047: an identifier that will not decode is reported as
/// unknown, with the standard incompleteness pair, never as event 0.
///
/// What an examiner learns: which Windows event a record is, and where it sits
/// in the log's record sequence. 0 is a value Windows itself logs, so writing 0
/// for an ID that could not be read produced a record indistinguishable from a
/// genuine event 0: filtering a log by event ID, counting how often an ID
/// occurs, or arguing a gap from record numbers all silently absorbed records
/// whose identifiers were never established.
#[test]
fn an_undecodable_event_id_is_reported_as_unknown_not_as_event_0() {
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" />
            <EventID>4624Q</EventID>
            <EventRecordID>0x1F</EventRecordID>
            <Computer>WORKSTATION01</Computer>
            <Channel>Security</Channel>
        </System>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();
    assert_eq!(
        metadata.event_id, None,
        "an EventID that will not parse is unknown, not event 0: 0 is a real ID"
    );
    assert_eq!(metadata.event_record_id, None);
    // The text that defeated the decoder is preserved, not thrown away.
    assert_eq!(metadata.event_id_raw.as_deref(), Some("4624Q"));
    assert_eq!(metadata.event_record_id_raw.as_deref(), Some("0x1F"));

    let short_desc = EvtxParser::get_event_description(
        metadata.event_id,
        &metadata.provider_name,
        &metadata.channel,
    );
    assert!(
        !short_desc.contains("Event ID 0"),
        "the summary line must not name an ID this record never carried: {short_desc}"
    );

    let entry = log_entry_metadata(&metadata, &short_desc, "Information", xml);
    assert_eq!(
        entry["event_id"],
        serde_json::Value::Null,
        "the emitted record must say the ID is unknown; a 0 here reads as event 0"
    );
    assert_eq!(entry["event_record_id"], serde_json::Value::Null);
    assert_eq!(entry["content_incomplete"], true);
    assert_eq!(entry["content_incomplete_reason"], "unresolved_structure");
    let detail = entry["content_incomplete_detail"]
        .as_str()
        .expect("the pair carries the sentence naming which identifier is unknown");
    assert!(detail.contains("EventID"), "detail was: {detail}");
    assert!(detail.contains("EventRecordID"), "detail was: {detail}");
    assert_eq!(entry["event_id_raw"], "4624Q");
    assert_eq!(entry["event_record_id_raw"], "0x1F");

    // The timeline is where an invented ID does the most damage: it reads as a
    // sequence of things the machine did. Only the timeline_events columns
    // survive the insert, so the marker has to be inside full_details.
    let timeline = timeline_metadata(
        &metadata,
        "plugin.windows.evtx_parser",
        &short_desc,
        "Information",
    );
    let raw_details = timeline["full_details"]
        .as_str()
        .expect("full_details is a string");
    let details: serde_json::Value =
        serde_json::from_str(raw_details).expect("full_details must be valid JSON");
    assert_eq!(details["event_id"], serde_json::Value::Null);
    assert_eq!(details["event_record_id"], serde_json::Value::Null);
    assert_eq!(details["content_incomplete"], true);
    assert_eq!(details["content_incomplete_reason"], "unresolved_structure");
}

/// The counterpart to the marker: a record whose identifiers decoded must NOT
/// be stamped. A flag on every event log entry would tell an examiner nothing,
/// and would make the records that really are unreadable invisible again.
#[test]
fn a_record_with_readable_identifiers_carries_no_incompleteness_marker() {
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" />
            <EventID>4624</EventID>
            <EventRecordID>12345</EventRecordID>
            <Computer>WORKSTATION01</Computer>
            <Channel>Security</Channel>
        </System>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();
    let entry = log_entry_metadata(&metadata, "Account logon (successful)", "Information", xml);

    assert_eq!(entry["event_id"], 4624);
    assert_eq!(entry["event_record_id"], 12345);
    assert!(entry.get("content_incomplete").is_none());
    assert!(entry.get("content_incomplete_reason").is_none());
    assert!(entry.get("event_id_raw").is_none());
    assert!(entry.get("event_record_id_raw").is_none());
}

/// Event ID 0 is a value Windows genuinely logs, and it must survive as a
/// finding in its own right -- distinct from an ID that could not be read.
#[test]
fn a_genuine_event_id_0_is_kept_and_is_not_marked_unreadable() {
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Custom-Provider" />
            <EventID>0</EventID>
            <EventRecordID>0</EventRecordID>
            <Computer>WORKSTATION01</Computer>
            <Channel>Application</Channel>
        </System>
    </Event>"#;

    let metadata = EvtxParser::parse_event_xml(xml).unwrap();
    assert_eq!(metadata.event_id, Some(0));
    assert_eq!(metadata.event_record_id, Some(0));

    let entry = log_entry_metadata(&metadata, "Custom-Provider Event ID 0", "Information", xml);
    assert_eq!(entry["event_id"], 0);
    assert!(
        entry.get("content_incomplete").is_none(),
        "a record that really did log event 0 is complete, and must not be \
         marked as one this parser could not read"
    );
}

#[test]
fn test_get_event_description_security_4624() {
    let desc = EvtxParser::get_event_description(
        Some(4624),
        "Microsoft-Windows-Security-Auditing",
        "Security",
    );
    assert_eq!(desc, "Account logon (successful)");
}

#[test]
fn test_get_event_description_security_4625() {
    let desc = EvtxParser::get_event_description(Some(4625), "Sec-Audit", "Security");
    assert_eq!(desc, "Account logon (failed)");
}

#[test]
fn test_get_event_description_security_4688() {
    let desc = EvtxParser::get_event_description(Some(4688), "Audit", "Security");
    assert_eq!(desc, "Process created");
}

#[test]
fn test_get_event_description_system_6009() {
    let desc = EvtxParser::get_event_description(Some(6009), "Kernel", "System");
    assert_eq!(desc, "System boot");
}

#[test]
fn test_get_event_description_unknown() {
    let desc = EvtxParser::get_event_description(Some(9999), "CustomProvider", "Custom");
    assert_eq!(desc, "CustomProvider Event ID 9999");
}

#[test]
fn test_get_event_description_unreadable_id_names_no_id() {
    // The description an examiner reads first must not fill the gap with a
    // number. "Provider Event ID 0" read as a genuine event 0 (B8-047).
    let desc = EvtxParser::get_event_description(None, "CustomProvider", "Security");
    assert_eq!(desc, "CustomProvider event (Event ID unreadable)");
}

#[test]
fn test_get_level_description() {
    assert_eq!(EvtxParser::get_level_description(Some(1)), "Critical");
    assert_eq!(EvtxParser::get_level_description(Some(2)), "Error");
    assert_eq!(EvtxParser::get_level_description(Some(3)), "Warning");
    assert_eq!(EvtxParser::get_level_description(Some(4)), "Information");
    assert_eq!(EvtxParser::get_level_description(Some(5)), "Verbose");
    assert_eq!(EvtxParser::get_level_description(None), "Unknown");
    assert_eq!(EvtxParser::get_level_description(Some(99)), "Unknown");
}

#[test]
fn test_module_metadata() {
    let parser = EvtxParser;

    assert_eq!(parser.id(), "plugin.windows.evtx_parser");
    assert_eq!(parser.version(), env!("CARGO_PKG_VERSION"));

    let subscriptions = parser.subscribes_to();
    assert!(subscriptions.contains(&ArtifactType::FileEntry));
    assert!(subscriptions.contains(&ArtifactType::SystemArtifact));

    assert_eq!(parser.input_capability(), InputCapability::Stream);
}

#[test]
fn test_process_non_evtx_file() {
    let parser = EvtxParser;
    let case_id = Uuid::new_v4();

    // Create artifact with non-EVTX data
    let non_evtx_data = vec![0u8; 100]; // Random data
    let data_source: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(non_evtx_data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "test.bin"}),
    );

    // Should return empty vec (not an EVTX file)
    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_process_artifact_without_data_source() {
    let parser = EvtxParser;
    let case_id = Uuid::new_v4();

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        None, // No data source
        json!({"name": "test.evtx"}),
    );

    // With no data source, module returns Ok(empty) instead of Err (expected for carved files)
    let result = parser.process(&artifact);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

// Integration tests with real EVTX files
#[test]
fn test_parse_real_evtx_sample() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/sample.evtx");
    if !test_file.exists() {
        eprintln!("Skipping integration test: sample.evtx not found");
        return;
    }

    let parser = EvtxParser;
    let case_id = Uuid::new_v4();

    // Load real EVTX file
    let data = fs::read(test_file).expect("Failed to read sample.evtx");
    let data_source: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "sample.evtx"}),
    );

    // Process the EVTX file
    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Failed to parse sample.evtx: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();

    // Should produce artifacts (ParsedRecord + TimelineEvent for each event)
    assert!(!artifacts.is_empty(), "No events parsed from sample.evtx");

    // Each event produces 2 artifacts (ParsedRecord + TimelineEvent). A log
    // with undecodable records also carries one status record; exclude it.
    let event_artifacts = artifacts
        .iter()
        .filter(|a| a.metadata["type"] != "EvtxParseStatus")
        .count();
    assert_eq!(
        event_artifacts % 2,
        0,
        "Expected even number of artifacts (ParsedRecord + TimelineEvent pairs)"
    );

    let event_count = event_artifacts / 2;
    println!("Parsed {} events from sample.evtx", event_count);

    // Verify first artifact is a ParsedRecord
    assert_eq!(artifacts[0].artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(artifacts[0].metadata["type"], "EvtxLogEntry");

    // Verify second artifact is a TimelineEvent. Its timestamp is RFC 3339, not
    // an integer: whole seconds would drop the FILETIME sub-second field that
    // orders events logged in the same second.
    assert_eq!(artifacts[1].artifact_type, ArtifactType::TimelineEvent);
    let ts = artifacts[1].metadata["timestamp"]
        .as_str()
        .expect("timeline timestamp must be an RFC 3339 string");
    chrono::DateTime::parse_from_rfc3339(ts).expect("timeline timestamp must parse as RFC 3339");
    assert!(artifacts[1].metadata["short_desc"].is_string());

    // The ParsedRecord keeps whole seconds AND the sub-second remainder, and
    // the two must describe the same instant.
    let m = &artifacts[0].metadata;
    let secs = m["timestamp"].as_i64().expect("whole seconds");
    let nanos = m["timestamp_subsec_nanos"]
        .as_u64()
        .expect("sub-second nanoseconds") as u32;
    let utc =
        chrono::DateTime::parse_from_rfc3339(m["timestamp_utc"].as_str().expect("timestamp_utc"))
            .expect("timestamp_utc must parse as RFC 3339");
    assert_eq!(utc.timestamp(), secs);
    assert_eq!(utc.timestamp_subsec_nanos(), nanos);
}

/// Regression for the whole-second truncation: two events logged inside the
/// same second must remain distinguishable and orderable.
///
/// What an examiner learns: the exact instant each Windows event was written,
/// to the 100 ns FILETIME resolution. A wrong answer here reads as several
/// events sharing one identical time, so an intrusion sequence (logon, then
/// process creation, then service install) cannot be ordered at all.
#[test]
fn same_second_events_keep_their_sub_second_ordering() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/System.evtx");
    if !test_file.exists() {
        eprintln!("Skipping integration test: System.evtx not found");
        return;
    }
    let data = fs::read(test_file).expect("Failed to read System.evtx");
    let data_source: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "System.evtx"}),
    );

    let artifacts = EvtxParser.process(&artifact).unwrap();
    let nanos: Vec<u64> = artifacts
        .iter()
        .filter(|a| a.metadata["type"] == "EvtxLogEntry")
        .filter_map(|a| a.metadata["timestamp_subsec_nanos"].as_u64())
        .collect();
    assert!(!nanos.is_empty(), "no EVTX records parsed");
    assert!(
        nanos.iter().any(|&n| n != 0),
        "every event reported exactly zero sub-second nanoseconds, which means \
         the FILETIME remainder was truncated away"
    );
}

#[test]
fn test_parse_real_evtx_system() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/System.evtx");
    if !test_file.exists() {
        eprintln!("Skipping integration test: System.evtx not found");
        return;
    }

    let parser = EvtxParser;
    let case_id = Uuid::new_v4();

    let data = fs::read(test_file).expect("Failed to read System.evtx");
    let data_source: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "System.evtx"}),
    );

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Failed to parse System.evtx: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(!artifacts.is_empty(), "No events parsed from System.evtx");

    let event_count = artifacts.len() / 2;
    println!("Parsed {} events from System.evtx", event_count);

    // Verify we're parsing System channel events
    let parsed_records: Vec<_> = artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();

    // Check that at least some events are from System channel
    let system_events = parsed_records
        .iter()
        .filter(|a| a.metadata.get("channel").and_then(|v| v.as_str()) == Some("System"))
        .count();

    assert!(system_events > 0, "Expected System channel events");
    println!("Found {} System channel events", system_events);

    // Verify metadata structure
    for record in parsed_records.iter().take(5) {
        assert!(record.metadata.get("event_id").is_some());
        assert!(record.metadata.get("timestamp").is_some());
        assert!(record.metadata.get("computer_name").is_some());
        assert!(record.metadata.get("provider_name").is_some());
    }
}

#[test]
fn test_parse_real_evtx_system2() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/System2.evtx");
    if !test_file.exists() {
        eprintln!("Skipping integration test: System2.evtx not found");
        return;
    }

    let parser = EvtxParser;
    let case_id = Uuid::new_v4();

    let data = fs::read(test_file).expect("Failed to read System2.evtx");
    let data_source: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "System2.evtx"}),
    );

    let result = parser.process(&artifact);
    assert!(
        result.is_ok(),
        "Failed to parse System2.evtx: {:?}",
        result.err()
    );

    let artifacts = result.unwrap();
    assert!(!artifacts.is_empty(), "No events parsed from System2.evtx");

    println!("Parsed {} events from System2.evtx", artifacts.len() / 2);
}

#[test]
fn test_event_descriptions_from_real_data() {
    use std::fs;
    use std::path::Path;

    let test_file = Path::new("../test_data/sample.evtx");
    if !test_file.exists() {
        eprintln!("Skipping integration test: sample.evtx not found");
        return;
    }

    let parser = EvtxParser;
    let case_id = Uuid::new_v4();

    let data = fs::read(test_file).expect("Failed to read sample.evtx");
    let data_source: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(data));

    let artifact = Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        Some(data_source),
        json!({"name": "sample.evtx"}),
    );

    let result = parser.process(&artifact).unwrap();

    // Collect all ParsedRecord artifacts
    let parsed_records: Vec<_> = result
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
        .collect();

    // Verify short_desc is always present and non-empty
    for record in parsed_records.iter() {
        let short_desc = record
            .metadata
            .get("short_desc")
            .and_then(|v| v.as_str())
            .expect("short_desc should be present");

        assert!(!short_desc.is_empty(), "short_desc should not be empty");

        // Print a few examples
        if parsed_records.len() <= 5 {
            println!(
                "Event {}: {}",
                record.metadata.get("event_id").unwrap(),
                short_desc
            );
        }
    }
}

// Note: Integration tests with real EVTX files are now included above
// These tests use ../test_data/*.evtx files and verify end-to-end parsing

#[test]
fn an_event_log_with_undecodable_records_carries_a_visible_gap_marker() {
    // The status record is what tells an examiner that "no such event" may mean
    // "the record would not decode". Its shape is the contract.
    let status = parse_status_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        EvtxParseTally {
            events_parsed: 120,
            records_failed: 7,
            chunks_read: 5,
            ..Default::default()
        },
    );
    assert_eq!(status.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(status.metadata["type"], "EvtxParseStatus");
    assert_eq!(status.metadata["content_incomplete"], true);
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        "records_failed_to_parse"
    );
    assert_eq!(
        status.metadata["inventory_incomplete"], true,
        "a short event listing must carry the inventory flag too, not only the \
         content pair: an examiner asking whether the event list is complete \
         would otherwise read a partly decoded log as the whole log"
    );
    assert_eq!(status.metadata["events_parsed"], 120);
    assert_eq!(status.metadata["records_failed"], 7);
    assert_eq!(status.metadata["chunks_skipped"], 0);
    assert_eq!(status.metadata["walk_aborted"], false);
    assert_eq!(
        status.metadata["counts_are_floor"], false,
        "a walk that reached the end reports exact counts, not floors"
    );
}

#[test]
fn a_skipped_chunk_is_disclosed_as_its_own_kind_of_loss() {
    // A chunk abandoned after the decoder panicked lost an unknown number of
    // events, not a single record. The status must say so, and must not let
    // the coarse loss hide behind the exact `records_failed` count.
    let status = parse_status_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        EvtxParseTally {
            events_parsed: 500,
            chunks_skipped: 3,
            chunks_read: 9,
            partial_chunks: 1,
            ..Default::default()
        },
    );
    assert_eq!(status.metadata["content_incomplete"], true);
    assert_eq!(status.metadata["inventory_incomplete"], true);
    assert_eq!(status.metadata["chunks_skipped"], 3);
    assert_eq!(status.metadata["records_failed"], 0);
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        "chunks_skipped_after_decode_panic"
    );
}

/// RUSTSEC-2026-0194 regression, at the plugin's own boundary.
///
/// `seance_xml_util` proves the guard bounds the parser; this proves the guard
/// is actually in the EVTX path. Without it, one record's `<Provider>` element
/// carrying 200,000 attributes costs roughly 29 seconds of the ingest an
/// examiner is watching — and an EVTX file is evidence, so its records are
/// shaped by whoever controlled the machine.
#[test]
fn a_record_with_a_hostile_attribute_count_parses_in_bounded_time() {
    let mut provider = String::from("<Event><System><Provider");
    for i in 0..200_000 {
        provider.push_str(&format!(" a{i}=\"v\""));
    }
    provider.push_str(" Name=\"Svc\"/><EventID>4624</EventID></System></Event>");

    let start = std::time::Instant::now();
    let parsed = EvtxParser::parse_event_xml(&provider).expect("the record still parses");
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "parsing took {elapsed:?}; unguarded this record costs ~29 s, so anything \
         near that means the bounded reader is not in this path"
    );
    assert_eq!(
        parsed.event_id,
        Some(4624),
        "bounding the attributes must not cost the rest of the record"
    );
    // The `Name` attribute sits past the cap, so the provider is genuinely not
    // known — and the record has to say so rather than report a provider it
    // did not read.
    assert!(
        parsed
            .xml_findings
            .iter()
            .any(|(k, _)| *k == "xml_attributes_truncated"),
        "a record whose attributes were refused must disclose it; found: {:?}",
        parsed.xml_findings
    );
}

/// The ordinary case: a well-formed record carries no anomaly fields at all.
#[test]
fn an_ordinary_record_carries_no_xml_anomaly_fields() {
    let xml = r#"<Event><System><Provider Name="Svc"/><EventID>4624</EventID>
                 <Computer>PC1</Computer></System></Event>"#;
    let parsed = EvtxParser::parse_event_xml(xml).expect("parses");
    assert_eq!(parsed.provider_name, "Svc");
    assert!(
        parsed.xml_findings.is_empty(),
        "a clean record must not stamp anomaly noise onto its artifact"
    );
}

/// A malformed record that makes the upstream `evtx` 0.8.5 decoder panic (an
/// integer overflow on a length prefix, `utils/binxml_utils.rs:25`) must be
/// contained to its chunk, not allowed to lose the whole log.
///
/// Before the chunk-isolating walk, `parser.records()` decoded every chunk
/// behind one iterator, so this panic unwound the entire `process()` call and
/// the orchestrator's `catch_unwind` swallowed it: the file yielded nothing,
/// silently. A truncated or carved `.evtx` — ordinary real evidence — reaches
/// exactly this. The fixture is this crate's own stored fuzz reproducer.
///
/// The assertion is not "it parses": these bytes are one corrupt chunk and
/// there is nothing valid to recover. The assertion is that `process()`
/// RETURNS rather than panicking, and that when a chunk was lost it says so
/// with a disclosure record — never a silent empty result.
#[test]
fn a_record_that_panics_the_decoder_is_contained_to_its_chunk_not_the_whole_log() {
    let reproducer = include_bytes!("../tests_fixtures/evtx_overflow_reproducer.bin");
    // The fuzz harness prepends the EVTX magic so detection routes it here.
    let mut data = Vec::from(&b"ElfFile\0"[..]);
    data.extend_from_slice(reproducer);

    let data_source: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data_source),
        json!({ "name": "corrupt.evtx" }),
    );

    // The whole point: a panic in the decoder must not escape process().
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        EvtxParser.process(&artifact)
    }));
    let produced = out
        .expect("a decoder panic escaped process(): one bad record still loses the whole log")
        .expect("process() must return Ok on a corrupt log, recovering what it can");

    // Everything the decoder could not read must be disclosed. Here the single
    // chunk faulted, so the only artifact is the parse-status marker — and it
    // must be present, because a silent empty result is indistinguishable from
    // an empty log.
    let status: Vec<_> = produced
        .iter()
        .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("EvtxParseStatus"))
        .collect();
    assert_eq!(
        status.len(),
        1,
        "a log that lost a chunk to a decode panic must carry exactly one \
         parse-status marker; a silent empty result reads as an empty log"
    );
    let s = status[0];
    assert_eq!(s.metadata["content_incomplete"], true);
    assert_eq!(s.metadata["inventory_incomplete"], true);
    // The upstream decoder used to PANIC on this chunk (contained by the
    // per-chunk guard and counted under `chunks_skipped`); the vendored
    // decoder now returns an error for it (HUNT-037, `vendor/README.md`), which
    // the walk counts as an unreadable chunk or failed records. Either way the
    // loss is disclosed — that, not the mechanism, is what this test pins.
    let lost = s.metadata["chunks_skipped"].as_u64().unwrap_or(0)
        + s.metadata["chunks_unreadable"].as_u64().unwrap_or(0)
        + s.metadata["records_failed"].as_u64().unwrap_or(0);
    assert!(
        lost >= 1,
        "the marker must count at least the one chunk the corrupt record cost: {}",
        s.metadata
    );
}

/// An aborted walk is a much larger loss than a skipped chunk, and must not be
/// disclosed as one.
///
/// When a chunk HEADER faults, the parser's cursor is at an unknown offset and
/// the remainder of the file is never read. Reporting that as "1 chunk skipped"
/// understates the loss by however many chunks were left — on a large log, by
/// orders of magnitude. The status record has to say the walk stopped early and
/// that every count on it is a floor.
#[test]
fn an_aborted_walk_says_the_file_was_not_read_to_the_end_and_its_counts_are_a_floor() {
    let status = parse_status_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        EvtxParseTally {
            events_parsed: 400,
            chunks_read: 3,
            walk_aborted: true,
            ..Default::default()
        },
    );
    assert_eq!(status.metadata["walk_aborted"], true);
    assert_eq!(
        status.metadata["counts_are_floor"], true,
        "if the file was not read to the end, no loss count on this record can be a total"
    );
    assert_eq!(status.metadata["chunks_read"], 3);
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        "chunk_walk_aborted_after_decode_panic"
    );
    let message = status.metadata["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("NOT read to the end") && message.contains("FLOOR"),
        "the message must say the file was not finished and the counts are floors: {message}"
    );
}

/// A chunk that will not READ is a chunk-sized loss and must not be counted as
/// a failed record: `records_failed` is documented as exact and per-record, and
/// folding a whole unreadable chunk into it understates the loss.
#[test]
fn an_unreadable_chunk_is_counted_apart_from_failed_records() {
    let status = parse_status_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        EvtxParseTally {
            events_parsed: 10,
            chunks_unreadable: 2,
            chunks_read: 4,
            ..Default::default()
        },
    );
    assert_eq!(status.metadata["chunks_unreadable"], 2);
    assert_eq!(
        status.metadata["records_failed"], 0,
        "a chunk that would not read is not a failed record"
    );
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        "chunks_unreadable"
    );
}

/// Records decoded before a chunk faulted are evidence in hand and are kept.
#[test]
fn a_partially_recovered_chunk_is_reported_as_such() {
    let status = parse_status_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        EvtxParseTally {
            events_parsed: 42,
            chunks_skipped: 1,
            chunks_read: 6,
            partial_chunks: 1,
            ..Default::default()
        },
    );
    assert_eq!(status.metadata["chunks_partially_recovered"], 1);
    assert_eq!(status.metadata["chunks_skipped"], 1);
    assert_eq!(
        status.metadata["events_parsed"], 42,
        "events recovered before the fault are kept, not discarded with the unwind"
    );
}

/// A chunk whose string or template table loops is refused before the decoder
/// sees it (HUNT-037). The upstream cache population follows `next` pointers
/// with no termination check; a self-referential entry spun `process()` for
/// more than ten minutes on the stored reproducer.
#[test]
fn a_chunk_whose_table_chain_cycles_is_refused_not_followed_for_ever() {
    use super::chunk_tables_walkable;
    let mut chunk = vec![0u8; 65536];
    chunk[..8].copy_from_slice(b"ElfChnk\0");
    // Clean tables walk.
    assert!(chunk_tables_walkable(&chunk).is_ok());

    // String bucket 0 -> entry at 0x200 -> entry at 0x300 -> back to 0x200.
    chunk[0x80..0x84].copy_from_slice(&0x200u32.to_le_bytes());
    chunk[0x200..0x204].copy_from_slice(&0x300u32.to_le_bytes());
    chunk[0x300..0x304].copy_from_slice(&0x200u32.to_le_bytes());
    let why = chunk_tables_walkable(&chunk).expect_err("a cycle must be refused");
    assert!(
        why.contains("string table bucket 0") && why.contains("cycle"),
        "{why}"
    );

    // A self-loop in a template bucket, with the string table sound again.
    chunk[0x300..0x304].copy_from_slice(&0u32.to_le_bytes());
    assert!(chunk_tables_walkable(&chunk).is_ok());
    chunk[0x180 + 4 * 5..0x180 + 4 * 6].copy_from_slice(&0x400u32.to_le_bytes());
    chunk[0x400..0x404].copy_from_slice(&0x400u32.to_le_bytes());
    let why = chunk_tables_walkable(&chunk).expect_err("a self-loop must be refused");
    assert!(why.contains("template table bucket 5"), "{why}");

    // A link past the end of the chunk is NOT refused here: the decoder's own
    // read fails on it, finitely, and the chunk keeps the disclosure that
    // path already gives it.
    chunk[0x400..0x404].copy_from_slice(&0u32.to_le_bytes());
    chunk[0x80..0x84].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
    assert!(chunk_tables_walkable(&chunk).is_ok());
}

/// The stored reproducer, end to end: `process()` returns, promptly, and says
/// a chunk was not read. Run on its own thread so a regression fails the test
/// instead of hanging the suite.
#[test]
fn the_string_table_cycle_reproducer_is_processed_promptly_and_disclosed() {
    let reproducer = include_bytes!("../tests_fixtures/evtx_string_table_cycle_reproducer.bin");
    let mut data = Vec::with_capacity(8 + reproducer.len());
    data.extend_from_slice(b"ElfFile\0");
    data.extend_from_slice(reproducer);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::SystemArtifact,
            Some(Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(data),
            )),
            serde_json::json!({ "name": "cycle.evtx" }),
        );
        let _ = tx.send(EvtxParser.process(&artifact));
    });
    let result = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("process() must return: the decoder must not be sent round a cycle");
    let artifacts = result.expect("a corrupt chunk is disclosed, not an error");
    let summary = artifacts
        .iter()
        .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("evtx_parse_status"))
        .or_else(|| {
            artifacts
                .iter()
                .find(|a| a.metadata.get("chunks_unreadable").is_some())
        })
        .expect("the parse-status record must be emitted");
    assert!(
        summary.metadata["chunks_unreadable"].as_u64().unwrap_or(0) >= 1,
        "the refused chunk must be counted: {}",
        summary.metadata
    );
}

/// **The four WLAN-AutoConfig events say which of them happened.** This
/// channel is where a wireless JOIN TIME is: a profile on disk says the
/// machine was configured for a network, and 8001 says it was on it. The ids
/// and their meanings are as EvtxECmd's vendored maps document them
/// (`reference/evtx/evtx/Maps/Microsoft-Windows-WLAN-AutoConfig-*`), and the
/// four are kept apart because a report that called an attempt a connection
/// would put a machine on a network it never joined.
#[test]
fn the_wireless_channels_four_events_are_named_and_kept_apart() {
    let channel = "Microsoft-Windows-WLAN-AutoConfig/Operational";
    let provider = "Microsoft-Windows-WLAN-AutoConfig";
    assert_eq!(
        EvtxParser::get_event_description(Some(8000), provider, channel),
        "Wireless connection attempted"
    );
    assert_eq!(
        EvtxParser::get_event_description(Some(8001), provider, channel),
        "Wireless network connected"
    );
    assert_eq!(
        EvtxParser::get_event_description(Some(8002), provider, channel),
        "Wireless connection failed"
    );
    assert_eq!(
        EvtxParser::get_event_description(Some(8003), provider, channel),
        "Wireless network disconnected"
    );
    // An id on that channel this build does not name falls back to the
    // provider and the number, rather than being described as one of the four.
    assert_eq!(
        EvtxParser::get_event_description(Some(11004), provider, channel),
        format!("{provider} Event ID 11004")
    );
    // And the same ids on another channel are not these events: 8001 is a
    // number many providers use.
    assert_eq!(
        EvtxParser::get_event_description(Some(8001), "Some-Other-Provider", "Application"),
        "Some-Other-Provider Event ID 8001"
    );
}

/// A chunk header in the real `ElfChnk` layout: magic, the four record
/// numbers, `header_size` 128 at 0x28, `last_event_record_data_offset` at
/// 0x2C, `free_space_offset` at 0x30, the data CRC at 0x34 and the flags at
/// 0x78. Everything the vendored header reader needs, and nothing more.
fn chunk_header_bytes(free_space_offset: u32, total_len: usize) -> Vec<u8> {
    let mut data = vec![0u8; total_len];
    data[..8].copy_from_slice(b"ElfChnk\0");
    data[0x08..0x10].copy_from_slice(&1u64.to_le_bytes());
    data[0x10..0x18].copy_from_slice(&90u64.to_le_bytes());
    data[0x18..0x20].copy_from_slice(&195u64.to_le_bytes());
    data[0x20..0x28].copy_from_slice(&284u64.to_le_bytes());
    data[0x28..0x2C].copy_from_slice(&128u32.to_le_bytes());
    data[0x2C..0x30].copy_from_slice(&(free_space_offset - 616).to_le_bytes());
    data[0x30..0x34].copy_from_slice(&free_space_offset.to_le_bytes());
    data
}

/// `HUNT-164`: the vendored `evtx` crate's `validate_data_checksum` sliced
/// `data[512..free_space_offset]` unchecked, so a chunk cut short by the end
/// of its file — or carved from free space, which is how a truncated chunk
/// usually arrives — panicked with an index out of bounds. Bounded now: the
/// bytes the CRC covers are not all there, so the checksum cannot be said to
/// hold and the answer is `false`, never a panic.
#[test]
fn the_vendored_data_checksum_answers_false_on_a_truncated_chunk_rather_than_panicking() {
    // A chunk whose header says its records run to 64,000 but of which only
    // 60,000 bytes survive, as with plaso's `System2.evtx` third chunk.
    let truncated = chunk_header_bytes(64_000, 60_000);
    let chunk = evtx::EvtxChunkData::new(truncated, false).expect("the header reads");
    let verdict = std::panic::catch_unwind(|| chunk.validate_data_checksum());
    assert_eq!(
        verdict.ok(),
        Some(false),
        "a checksum over bytes that are not there is not valid, and must not panic"
    );
    // A free-space offset inside the header itself is a corrupt field; the
    // slice start would pass its end.
    let mut inverted = chunk_header_bytes(616, 4_096);
    inverted[0x30..0x34].copy_from_slice(&100u32.to_le_bytes());
    let chunk = evtx::EvtxChunkData::new(inverted, false).expect("the header reads");
    let verdict = std::panic::catch_unwind(|| chunk.validate_data_checksum());
    assert_eq!(verdict.ok(), Some(false));
}

/// `HUNT-162`, the part that needs no corpus: which tail is a chunk the file
/// ends inside, and how the walk's status record reports one.
#[test]
fn a_tail_that_opens_with_the_chunk_magic_is_a_truncated_chunk_and_nothing_else_is() {
    let whole = 4096 + 65_536;
    let mut cut = vec![0u8; whole];
    cut.extend_from_slice(b"ElfChnk\0");
    cut.extend_from_slice(&[0u8; 100]);
    assert_eq!(
        truncated_tail_chunk(&MockEvtxSource::new(cut)),
        Some((whole as u64, 108))
    );
    // Padding after the last whole chunk is not a lost chunk.
    assert_eq!(
        truncated_tail_chunk(&MockEvtxSource::new(vec![0u8; whole + 4000])),
        None
    );
    // A file that ends on a chunk boundary has no tail at all.
    assert_eq!(
        truncated_tail_chunk(&MockEvtxSource::new(vec![0u8; whole])),
        None
    );

    let status = parse_status_artifact(
        Uuid::new_v4(),
        Uuid::new_v4(),
        EvtxParseTally {
            events_parsed: 194,
            chunks_read: 2,
            truncated_tail: Some((135_168, 64_832)),
            ..Default::default()
        },
    );
    let m = &status.metadata;
    assert_eq!(
        m["content_incomplete_reason"],
        "chunk_truncated_at_end_of_file"
    );
    assert_eq!(m["inventory_incomplete"], true);
    assert_eq!(m["chunks_truncated_at_eof"], 1);
    assert_eq!(m["truncated_chunk_offset"], 135_168);
    assert_eq!(m["truncated_chunk_bytes_present"], 64_832);
    assert_eq!(
        m["counts_are_floor"], false,
        "the walk reached the end of the file; its counts are exact"
    );
    let message = m["message"].as_str().unwrap();
    assert!(
        !message.contains("could not be decoded"),
        "nothing failed to decode; the chunk was never handed to the decoder: {message}"
    );
    assert!(message.contains("EvtxRecoveryStatus"), "{message}");
}

/// HUNT-277: the event-log parser reads a shadow-copy prior version and only
/// that from among the `ParsedRecord`s; any other parsed record is not read.
#[test]
fn a_parsed_record_that_is_not_a_prior_version_is_not_read() {
    let src: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(vec![0u8; 4096]));
    let other = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(src),
        serde_json::json!({ "type": "SomethingElse" }),
    );
    assert!(EvtxParser.process(&other).unwrap().is_empty());
    assert!(EvtxParser
        .subscribes_to()
        .contains(&ArtifactType::ParsedRecord));
}
