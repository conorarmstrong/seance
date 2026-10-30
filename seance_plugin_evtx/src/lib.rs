#![forbid(unsafe_code)]
use anyhow::Result;
use chrono::{DateTime, Utc};
use evtx::EvtxParser as InnerEvtxParser;
use quick_xml::events::Event;
use quick_xml::Reader;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::SourceCursor,
    file_detection::{detect_file_type, DetectedFileType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_xml_util::XmlGuard;
use serde_json::json;
use tracing::{debug, info, warn};

mod recovery;
use recovery::{LiveCoverage, RecoveredRecord, Recovery};

pub struct EvtxParser;

/// Parsed EVTX event metadata
#[derive(Debug, Clone)]
struct EventMetadata {
    /// The record's `EventID`, or `None` when the element was absent or its
    /// text would not parse as a number.
    ///
    /// Optional rather than defaulted to 0: 0 is itself a valid Windows event
    /// identifier, so a record whose ID could not be read was indistinguishable
    /// from one that genuinely logged event 0. An examiner filtering or
    /// counting by event ID was handed an ID this parser invented (B8-047).
    event_id: Option<u32>,
    /// The `EventID` element's text when it was present but would not parse.
    /// Kept so the value that defeated the decoder can still be read; `None`
    /// means the element itself was absent, which is a different fact.
    event_id_raw: Option<String>,
    /// The record's `EventRecordID`, on the same terms as
    /// [`EventMetadata::event_id`]. Record numbers are what a claimed gap in a
    /// log is argued from, so a fabricated one is worse here, not better.
    event_record_id: Option<u64>,
    /// The `EventRecordID` element's text when it was present but would not
    /// parse. See [`EventMetadata::event_id_raw`].
    event_record_id_raw: Option<String>,
    /// Whole Unix seconds of the record's `TimeCreated`.
    timestamp: i64,
    /// Nanoseconds past [`EventMetadata::timestamp`].
    ///
    /// Windows writes event times as FILETIME, which resolves to 100 ns. Two
    /// events in the same second are ordered by this field and nothing else,
    /// and same-second ordering is exactly what decides whether a process
    /// started before or after the logon it is attributed to. Dropping it
    /// leaves an intrusion sequence that cannot be ordered against the
    /// prefetch, MFT and registry timestamps it must be correlated with.
    timestamp_subsec_nanos: u32,
    /// The record's `TimeCreated` as RFC 3339 with full sub-second precision.
    /// This is what reaches `timeline_events.timestamp_subsec_nanos`; an
    /// integer-seconds timeline timestamp silently stores zero nanoseconds.
    timestamp_utc: String,
    computer_name: String,
    provider_name: String,
    channel: String,
    level: Option<u8>,
    task: Option<u16>,
    keywords: Option<String>,
    user_sid: Option<String>,
    /// Name/value pairs from the event's `EventData`/`Data` and `UserData`
    /// sections. This is the event-specific payload (process names, command
    /// lines, subject/target users, logon details, ...) that the System header
    /// alone does not carry.
    event_data: serde_json::Map<String, serde_json::Value>,
    /// What the bounded XML reader refused or found malformed in this record,
    /// ready to stamp onto the artifact. Empty for the overwhelming majority
    /// of records, which are well-formed and nowhere near any cap.
    ///
    /// Carried per record rather than per file because a single crafted record
    /// in an otherwise ordinary log is the case that matters: saying "this log
    /// contained an anomaly" would leave an examiner to find which of 200,000
    /// records it was.
    xml_findings: Vec<(&'static str, serde_json::Value)>,
}

/// Split a record's `TimeCreated` into the three forms the case needs:
/// whole Unix seconds, the nanosecond remainder, and RFC 3339 with full
/// sub-second precision.
///
/// Forensic meaning: Windows records event times as FILETIME, resolving to
/// 100 ns. Keeping only whole seconds collapses every event logged inside one
/// second onto a single instant, and same-second order is precisely what
/// establishes whether a process start preceded or followed the logon it is
/// attributed to. A wrong answer here does not look wrong -- it looks like a
/// batch of simultaneous events -- so the remainder must be carried
/// explicitly. `chrono`'s `to_rfc3339` emits as many sub-second digits as the
/// value needs, so no precision is lost in the string form either.
fn record_times(ts: DateTime<Utc>) -> (i64, u32, String) {
    (ts.timestamp(), ts.timestamp_subsec_nanos(), ts.to_rfc3339())
}

/// Insert `key`->`val` without clobbering an existing key. Duplicate `Data`
/// names (or repeated UserData element names) are suffixed rather than silently
/// overwritten, so no payload field is lost.
fn insert_unique(map: &mut serde_json::Map<String, serde_json::Value>, key: String, val: String) {
    if !map.contains_key(&key) {
        map.insert(key, serde_json::Value::String(val));
        return;
    }
    let mut n = 2;
    loop {
        let candidate = format!("{key}_{n}");
        if !map.contains_key(&candidate) {
            map.insert(candidate, serde_json::Value::String(val));
            return;
        }
        n += 1;
    }
}

impl EvtxParser {
    /// Parse event metadata from XML
    fn parse_event_xml(xml: &str) -> Result<EventMetadata, String> {
        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        // Every byte below came off the machine under examination. The guard
        // is what keeps a crafted record's attribute list from costing tens of
        // seconds -- see `seance_xml_util` for the measurements.
        let mut guard = XmlGuard::default();

        // Absent elements stay `None`: a record with no EventID at all is not a
        // record of event 0.
        let mut event_id: Option<u32> = None;
        let mut event_id_raw: Option<String> = None;
        let mut event_record_id: Option<u64> = None;
        let mut event_record_id_raw: Option<String> = None;
        let mut computer_name = String::from("Unknown");
        let mut provider_name = String::from("Unknown");
        let mut channel = String::from("Unknown");
        let mut level: Option<u8> = None;
        let mut task: Option<u16> = None;
        let mut keywords: Option<String> = None;
        let mut user_sid: Option<String> = None;

        let mut in_system = false;
        let mut in_event_id = false;
        let mut in_event_record_id = false;
        let mut in_computer = false;
        let mut in_channel = false;
        let mut in_level = false;
        let mut in_task = false;
        let mut in_keywords = false;

        // EventData / UserData payload extraction.
        let mut event_data = serde_json::Map::new();
        let mut in_event_data = false;
        let mut in_user_data = false;
        // Key the next Text event should be recorded under (set by the element
        // that opened it); cleared once its text is consumed.
        let mut current_data_key: Option<String> = None;
        let mut unnamed_index = 0usize;

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = e.name();
                    let tag = std::str::from_utf8(name.as_ref()).unwrap_or("");

                    match tag {
                        "System" => in_system = true,
                        "EventID" if in_system => in_event_id = true,
                        "EventRecordID" if in_system => in_event_record_id = true,
                        "Computer" if in_system => in_computer = true,
                        "Channel" if in_system => in_channel = true,
                        "Level" if in_system => in_level = true,
                        "Task" if in_system => in_task = true,
                        "Keywords" if in_system => in_keywords = true,
                        "Provider" if in_system => {
                            // Extract Name attribute from Provider element
                            for attr in guard.attributes(&e) {
                                if std::str::from_utf8(attr.key.as_ref()).unwrap_or("") == "Name" {
                                    provider_name = std::str::from_utf8(&attr.value)
                                        .unwrap_or("Unknown")
                                        .to_string();
                                }
                            }
                        }
                        "Security" if in_system => {
                            // Extract UserID from Security element
                            for attr in guard.attributes(&e) {
                                if std::str::from_utf8(attr.key.as_ref()).unwrap_or("") == "UserID"
                                {
                                    user_sid = Some(
                                        std::str::from_utf8(&attr.value).unwrap_or("").to_string(),
                                    );
                                }
                            }
                        }
                        "EventData" => in_event_data = true,
                        "UserData" => in_user_data = true,
                        _ if in_event_data => {
                            // Inside <EventData>: entries are <Data Name="...">value</Data>
                            // (named) or positional <Data>value</Data>.
                            let key = if tag == "Data" {
                                guard
                                    .attributes(&e)
                                    .into_iter()
                                    .find(|a| {
                                        std::str::from_utf8(a.key.as_ref()).unwrap_or("") == "Name"
                                    })
                                    .map(|a| {
                                        std::str::from_utf8(&a.value).unwrap_or("").to_string()
                                    })
                                    .unwrap_or_else(|| {
                                        unnamed_index += 1;
                                        format!("Data{unnamed_index}")
                                    })
                            } else {
                                tag.to_string()
                            };
                            current_data_key = Some(key);
                        }
                        _ if in_user_data => {
                            // Inside <UserData>: capture each leaf element's
                            // tag -> text. The provider wrapper element also
                            // opens a key, but it carries no direct text (only
                            // child elements), so nothing is recorded for it.
                            current_data_key = Some(tag.to_string());
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape().unwrap_or_default();
                    if in_event_id {
                        event_id = text.parse().ok();
                        if event_id.is_none() {
                            event_id_raw = Some(text.to_string());
                        }
                        in_event_id = false;
                    } else if in_event_record_id {
                        event_record_id = text.parse().ok();
                        if event_record_id.is_none() {
                            event_record_id_raw = Some(text.to_string());
                        }
                        in_event_record_id = false;
                    } else if in_computer {
                        computer_name = text.to_string();
                        in_computer = false;
                    } else if in_channel {
                        channel = text.to_string();
                        in_channel = false;
                    } else if in_level {
                        level = text.parse().ok();
                        in_level = false;
                    } else if in_task {
                        task = text.parse().ok();
                        in_task = false;
                    } else if in_keywords {
                        keywords = Some(text.to_string());
                        in_keywords = false;
                    } else if let Some(key) = current_data_key.take() {
                        // EventData/UserData value for the element just opened.
                        insert_unique(&mut event_data, key, text.to_string());
                    }
                }
                Ok(Event::End(e)) => {
                    let name = e.name();
                    let tag = std::str::from_utf8(name.as_ref()).unwrap_or("");
                    match tag {
                        "System" => in_system = false,
                        "EventData" => in_event_data = false,
                        "UserData" => in_user_data = false,
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(format!(
                        "Error parsing XML at position {}: {}",
                        reader.buffer_position(),
                        e
                    ));
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(EventMetadata {
            event_id,
            event_id_raw,
            event_record_id,
            event_record_id_raw,
            // All three time fields are set from evtx::Record by the caller,
            // which is the only place that holds the record's FILETIME.
            timestamp: 0,
            timestamp_subsec_nanos: 0,
            timestamp_utc: String::new(),
            computer_name,
            provider_name,
            channel,
            level,
            task,
            keywords,
            user_sid,
            event_data,
            xml_findings: guard.incompleteness_fields(),
        })
    }

    /// Generate a human-readable description for common event IDs
    ///
    /// Takes an `Option` so an unreadable ID cannot be described at all: the
    /// old signature could only be called with a number, and the number it was
    /// called with for an undecodable EventID was 0 -- which named this record
    /// "Event ID 0" in the summary an examiner reads first.
    fn get_event_description(event_id: Option<u32>, provider: &str, channel: &str) -> String {
        let Some(event_id) = event_id else {
            return format!("{} event (Event ID unreadable)", provider);
        };
        // Common Windows event IDs
        match (channel, event_id) {
            // Security log
            ("Security", 4624) => "Account logon (successful)".to_string(),
            ("Security", 4625) => "Account logon (failed)".to_string(),
            ("Security", 4634) => "Account logoff".to_string(),
            ("Security", 4648) => "Logon using explicit credentials".to_string(),
            ("Security", 4672) => "Special privileges assigned to new logon".to_string(),
            ("Security", 4688) => "Process created".to_string(),
            ("Security", 4689) => "Process exited".to_string(),
            ("Security", 4720) => "User account created".to_string(),
            ("Security", 4722) => "User account enabled".to_string(),
            ("Security", 4724) => "Password reset attempt".to_string(),
            ("Security", 4725) => "User account disabled".to_string(),
            ("Security", 4726) => "User account deleted".to_string(),
            ("Security", 4732) => "Member added to security-enabled local group".to_string(),
            ("Security", 4733) => "Member removed from security-enabled local group".to_string(),
            ("Security", 4756) => "Member added to security-enabled universal group".to_string(),
            ("Security", 4768) => "Kerberos authentication ticket (TGT) requested".to_string(),
            ("Security", 4769) => "Kerberos service ticket requested".to_string(),

            // System log
            ("System", 1074) => "System shutdown initiated".to_string(),
            ("System", 6005) => "Event Log service started".to_string(),
            ("System", 6006) => "Event Log service stopped".to_string(),
            ("System", 6009) => "System boot".to_string(),
            ("System", 7045) => "Service installed".to_string(),

            // Application log
            ("Application", 1000) => "Application error".to_string(),
            ("Application", 1001) => "Application crash (Windows Error Reporting)".to_string(),

            // Wireless (ROADMAP §4.3). This channel is where the JOIN TIMES
            // are: a WLAN profile on disk says the machine was configured for
            // a network, and 8001 says it was on it, at an instant, with the
            // SSID, the profile name, the authentication and the cipher in
            // the event's own data. The four ids and their meanings are as
            // EvtxECmd's maps document them
            // (`reference/evtx/evtx/Maps/Microsoft-Windows-WLAN-AutoConfig-*`,
            // which carry a real event of each shape), and the phrasing here
            // says which of "attempted", "succeeded", "failed" and
            // "disconnected" it is, because a report that called an attempt a
            // connection would put a machine on a network it never joined.
            ("Microsoft-Windows-WLAN-AutoConfig/Operational", 8000) => {
                "Wireless connection attempted".to_string()
            }
            ("Microsoft-Windows-WLAN-AutoConfig/Operational", 8001) => {
                "Wireless network connected".to_string()
            }
            ("Microsoft-Windows-WLAN-AutoConfig/Operational", 8002) => {
                "Wireless connection failed".to_string()
            }
            ("Microsoft-Windows-WLAN-AutoConfig/Operational", 8003) => {
                "Wireless network disconnected".to_string()
            }

            // Default
            _ => format!("{} Event ID {}", provider, event_id),
        }
    }

    /// Get severity level description
    fn get_level_description(level: Option<u8>) -> &'static str {
        match level {
            Some(1) => "Critical",
            Some(2) => "Error",
            Some(3) => "Warning",
            Some(4) => "Information",
            Some(5) => "Verbose",
            _ => "Unknown",
        }
    }
}

/// Offset of the 64 string-bucket offsets in a chunk header, and of the 32
/// template-bucket offsets that follow them (EVTX chunk header layout).
const CHUNK_STRING_TABLE: usize = 0x80;
const CHUNK_STRING_BUCKETS: usize = 64;
const CHUNK_TEMPLATE_TABLE: usize = 0x180;
const CHUNK_TEMPLATE_BUCKETS: usize = 32;
/// Bytes the decoder reads at a string entry before following its link
/// (`next` u32 + hash u16), and at a template entry (`next` u32 + GUID + size).
const STRING_ENTRY_HEAD: usize = 6;
const TEMPLATE_ENTRY_HEAD: usize = 24;

/// Whether the chunk's string and template tables can be walked to their end.
///
/// The upstream `evtx` decoder builds its caches by following each bucket's
/// `next` pointer until it reads zero — `StringCache::populate` and
/// `TemplateCache::populate` — with no check that the chain terminates. An
/// entry whose `next` points back at itself, or at an earlier entry in the
/// chain, sends it round for ever, inserting the same name into a `HashMap`
/// until the process is killed. Found by this crate's fuzz target: one such
/// chunk in an otherwise ordinary log stalled `process()` indefinitely (the
/// stored reproducer ran for more than ten minutes before it was stopped).
/// `catch_unwind` cannot help against a loop, so the tables are walked here
/// first, following exactly the pointers the decoder would follow, and a chunk
/// whose chain cycles or runs off the end of the chunk is refused as
/// unreadable — counted and disclosed like any other chunk that would not read.
///
/// Only CYCLES are refused. A link that runs off the end of the chunk ends the
/// walk here and is left to the decoder, which fails to read the entry and
/// reports the chunk as an error rather than looping — the existing
/// `chunk_panics` / `chunks_unreadable` accounting covers it, and the stored
/// overflow reproducer (whose string table does reach past its chunk) keeps
/// the disclosure it has always had.
pub(crate) fn chunk_tables_walkable(data: &[u8]) -> Result<(), String> {
    walk_table(
        data,
        CHUNK_STRING_TABLE,
        CHUNK_STRING_BUCKETS,
        STRING_ENTRY_HEAD,
        "string",
    )?;
    walk_table(
        data,
        CHUNK_TEMPLATE_TABLE,
        CHUNK_TEMPLATE_BUCKETS,
        TEMPLATE_ENTRY_HEAD,
        "template",
    )
}

fn walk_table(
    data: &[u8],
    table_at: usize,
    buckets: usize,
    entry_head: usize,
    what: &str,
) -> Result<(), String> {
    let u32_at = |at: usize| -> Option<u32> {
        data.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    // No chain can hold more distinct entries than fit in the chunk, so a walk
    // longer than that is a cycle whatever the visited set says. The set is
    // what names the cycle precisely; the cap is what bounds the worst case.
    let most_entries = data.len() / entry_head.max(1) + 1;
    for bucket in 0..buckets {
        let Some(mut offset) = u32_at(table_at + bucket * 4) else {
            // A chunk too short to hold its own header: the decoder refuses it
            // for the same reason, so there is nothing to walk.
            return Ok(());
        };
        let mut visited = std::collections::HashSet::new();
        let mut steps = 0usize;
        while offset != 0 {
            let at = offset as usize;
            if at + entry_head > data.len() {
                // Off the chunk: the decoder's own read fails here, finitely.
                break;
            }
            if !visited.insert(offset) {
                return Err(format!(
                    "{what} table bucket {bucket} forms a cycle at offset {offset}; the decoder would \
                     follow it for ever"
                ));
            }
            steps += 1;
            if steps > most_entries {
                return Err(format!(
                    "{what} table bucket {bucket} chains through more entries than the chunk can hold"
                ));
            }
            offset = u32_at(at).unwrap_or(0);
        }
    }
    Ok(())
}

impl ForensicsModule for EvtxParser {
    fn id(&self) -> &str {
        "plugin.windows.evtx_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl EvtxParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        debug!("EvtxParser processing artifact ID: {}", artifact.id);
        let mut produced_artifacts = Vec::new();

        // Use content-based detection instead of filename
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()),
        };

        let detected_type = detect_file_type(data_source.as_ref());
        let intact = detected_type == DetectedFileType::EvtxLog;
        // A log whose `ElfFile` header is gone -- overwritten, or never
        // present because these bytes are a fragment carved from free space --
        // is not an EVTX file to the detector, but its chunks are still
        // evidence. Such an input reaches the recovery pass when its name says
        // it is an event log or when a chunk signature sits in its head; every
        // other file is left alone, as before.
        let named_evtx = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .is_some_and(|n| n.to_ascii_lowercase().ends_with(".evtx"));
        if !intact && !named_evtx && !recovery::holds_chunk_signature(data_source.as_ref()) {
            return Ok(Vec::new());
        }

        let mut live = LiveCoverage::default();
        let mut intact_parsed = false;
        if intact {
            info!(
                "Detected EVTX file via content analysis (artifact ID: {})",
                artifact.id
            );
            match self.parse_intact(artifact, data_source, &mut produced_artifacts, &mut live) {
                Ok(()) => intact_parsed = true,
                // A file header that will not open is not the end of the
                // file: the chunks behind it are what recovery reads.
                Err(e) => warn!(
                    "EVTX file header on artifact {} would not open ({}); running chunk \
                     recovery only",
                    artifact.id, e
                ),
            }
        } else {
            info!(
                "No EVTX file header on artifact {}; running chunk recovery only",
                artifact.id
            );
        }

        // Everything the intact walk did not, or could not, read: chunks the
        // file header does not account for, chunks that would not decode,
        // records in chunk slack, and records whose chunk header is gone.
        let recovered = recovery::recover(data_source.as_ref(), &live);
        for record in &recovered.records {
            let (entry, timeline) =
                recovered_record_artifacts(artifact.case_id, artifact.id, self.id(), record);
            produced_artifacts.push(entry);
            produced_artifacts.extend(timeline);
        }
        if recovery_has_something_to_say(&recovered, intact_parsed) {
            produced_artifacts.push(recovery_status_artifact(
                artifact.case_id,
                artifact.id,
                &recovered,
            ));
        }

        Ok(produced_artifacts)
    }
}

impl EvtxParser {
    /// The walk of an intact file, from its `ElfFile` header, chunk by chunk.
    ///
    /// Records what it emitted into `live` so the recovery pass that follows
    /// can tell a chunk it decoded from one it lost, and never repeats a
    /// record that already left as a live event.
    fn parse_intact(
        &self,
        artifact: &Artifact,
        data_source: &std::sync::Arc<dyn seance_core::data_source::DataSource>,
        produced_artifacts: &mut Vec<Artifact>,
        live: &mut LiveCoverage,
    ) -> Result<(), ModuleError> {
        let cursor = SourceCursor::new(data_source.clone());

        let mut parser = InnerEvtxParser::from_read_seek(cursor).map_err(|e| {
            ModuleError::ParsingError(format!("Failed to create EVTX parser: {}", e))
        })?;

        let mut event_count = 0u64;
        let mut error_count = 0u64;
        // Chunks a panic aborted mid-decode. The upstream `evtx` 0.8.5 record
        // decoder can PANIC on a malformed record — an integer overflow on a
        // length prefix is one confirmed way (`utils/binxml_utils.rs`), found
        // by replaying this crate's own stored fuzz reproducer. `parser.records()`
        // decodes every chunk behind one iterator, so such a panic unwinds the
        // whole file and the orchestrator's `catch_unwind` swallows it: a single
        // bad record would silently lose EVERY event in the log. A truncated or
        // carved `.evtx` — ordinary real-world evidence — hits exactly this.
        // Walk chunk by chunk instead and isolate each chunk: one corrupt 64 KiB
        // chunk is lost and counted, every other chunk is recovered, and the
        // loss is disclosed by the parse-status record below. This is the same
        // skip-and-count contract the MFT and $LogFile parsers already keep.
        let mut chunk_panics = 0u64;
        // Chunks whose header or body would not READ (a magic/checksum failure,
        // a truncated tail). Counted apart from `records_failed`, which is a
        // per-record figure: a chunk that will not read is up to a chunk's worth
        // of events lost, and folding it into a record count understates it.
        let mut chunks_unreadable = 0u64;
        // Chunks whose header was read, whether or not their records decoded.
        let mut chunks_read = 0u64;
        // True when the walk stopped before the end of the file, so the count
        // of skipped chunks is a floor and the remainder was never examined.
        let mut walk_aborted = false;
        // Records recovered from a chunk that then panicked part-way through.
        let mut partial_chunks = 0u64;

        // `ParserSettings::default()` is what `InnerEvtxParser::from_read_seek`
        // configures the parser with, so this chunk walk decodes exactly as
        // `parser.records()` would. If the parser is ever built with
        // `with_configuration`, this must take the same settings or the walk
        // will silently ignore them.
        let settings = std::sync::Arc::new(evtx::ParserSettings::default());
        // Walked by chunk number rather than through `parser.chunks()` so the
        // offset of each chunk is known: the recovery pass needs to know which
        // chunks were read here and which records left them.
        let mut next_chunk_number = 0u64;
        loop {
            // Advancing to the next chunk parses a chunk header, which can
            // itself panic on corrupt bytes. If it does, the parser's cursor is
            // at an unknown offset and the chunk walk cannot safely resume, so
            // stop — every chunk read before this point is already recovered.
            let advanced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                parser.find_next_chunk(next_chunk_number)
            }));
            let (chunk_result, chunk_number) = match advanced {
                Ok(Some((c, n))) => (c, n),
                Ok(None) => break,
                Err(_) => {
                    // The parser's cursor is at an unknown offset, so the walk
                    // cannot safely resume: everything AFTER this point in the
                    // file is unread, not merely this one chunk. That is a
                    // different and much larger loss, and it is disclosed as
                    // its own fact rather than as "one chunk skipped".
                    walk_aborted = true;
                    warn!(
                        "EVTX chunk walk in artifact {} aborted at chunk {}: a chunk header \
                         panicked while decoding. Chunks before it were recovered; the remainder \
                         of the file was not read",
                        artifact.id, chunks_read
                    );
                    break;
                }
            };
            next_chunk_number = match chunk_number.checked_add(1) {
                Some(n) => n,
                None => break,
            };
            let chunk_offset = EVTX_FILE_HEADER_SIZE + chunk_number * EVTX_CHUNK_SIZE;
            let mut chunk_data = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    // A whole chunk that would not read, not a record.
                    chunks_unreadable += 1;
                    warn!(
                        "Failed to read an EVTX chunk from artifact {}: {}",
                        artifact.id, e
                    );
                    continue;
                }
            };
            chunks_read += 1;
            let mut live_ids = std::collections::HashSet::new();
            let mut chunk_lost_something = false;

            // The chunk owns its bytes, so a panic decoding it cannot corrupt
            // the parser: the walk continues at the next chunk. Records are
            // collected into owned values inside the guard so nothing borrowed
            // from the chunk escapes it.
            type ChunkRecord = std::result::Result<(DateTime<Utc>, String), String>;
            // Owned OUTSIDE the guard so that records already decoded when a
            // later record panics survive the unwind. They are valid evidence
            // that was in hand; discarding them would lose a chunk's worth of
            // events to one bad record at its end.
            let mut records: Vec<ChunkRecord> = Vec::new();
            let mut chunk_parse_failed: Option<String> = None;
            // Refuse a chunk whose string or template table would send the
            // upstream decoder round in a circle BEFORE handing it over: see
            // `chunk_tables_walkable`. A loop is not a panic, so nothing
            // below could have caught it.
            if let Err(why) = chunk_tables_walkable(&chunk_data.data) {
                // Not noted in `live`: the recovery pass re-reads the chunk
                // with its tables discarded, which is the relaxed decode the
                // refusal here leaves room for.
                chunks_unreadable += 1;
                warn!(
                    "EVTX chunk {} in artifact {} was not decoded: {}",
                    chunks_read, artifact.id, why
                );
                continue;
            }
            let extracted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match chunk_data.parse(settings.clone()) {
                    Err(e) => chunk_parse_failed = Some(format!("chunk parse failed: {e}")),
                    Ok(mut chunk) => {
                        for rec in chunk.iter() {
                            // Convert the upstream error to a String at once
                            // rather than carrying its 144-byte variant through
                            // a Result (clippy::result_large_err).
                            let decoded = match rec {
                                Ok(r) => r.into_xml().map_err(|e| format!("record decode: {e}")),
                                Err(e) => Err(format!("record read: {e}")),
                            };
                            records.push(decoded.map(|r| (r.timestamp, r.data)));
                        }
                    }
                }
            }));
            if extracted.is_err() {
                chunk_lost_something = true;
                chunk_panics += 1;
                if !records.is_empty() {
                    partial_chunks += 1;
                }
                warn!(
                    "An EVTX chunk in artifact {} panicked while decoding a record; {} record(s) \
                     recovered from it before the fault, the remainder of that chunk lost, and \
                     the rest of the log read normally",
                    artifact.id,
                    records.len()
                );
            }
            if let Some(e) = chunk_parse_failed {
                // The chunk header read but its body would not parse: again a
                // chunk-sized loss, not a record-sized one.
                chunk_lost_something = true;
                chunks_unreadable += 1;
                warn!(
                    "EVTX chunk in artifact {} did not parse: {}",
                    artifact.id, e
                );
            }
            for rec in records {
                let (timestamp_raw, event_xml) = match rec {
                    Ok(pair) => pair,
                    Err(e) => {
                        chunk_lost_something = true;
                        error_count += 1;
                        warn!(
                            "Failed to parse EVTX record from artifact {}: {}",
                            artifact.id, e
                        );
                        continue;
                    }
                };

                // The record carries a Windows FILETIME (100 ns resolution).
                // Keep whole seconds for the existing `timestamp` field AND
                // carry the remainder, so events logged within the same second
                // stay orderable.
                let (timestamp, timestamp_subsec_nanos, timestamp_utc) =
                    record_times(timestamp_raw);

                match Self::parse_event_xml(&event_xml) {
                    Ok(mut metadata) => {
                        metadata.timestamp = timestamp;
                        metadata.timestamp_subsec_nanos = timestamp_subsec_nanos;
                        metadata.timestamp_utc = timestamp_utc;
                        event_count += 1;
                        if let Some(id) = metadata.event_record_id {
                            live_ids.insert(id);
                        }

                        let short_desc = Self::get_event_description(
                            metadata.event_id,
                            &metadata.provider_name,
                            &metadata.channel,
                        );
                        let level_desc = Self::get_level_description(metadata.level);

                        let log_entry_artifact = Artifact::new(
                            artifact.case_id,
                            ArtifactType::ParsedRecord,
                            None,
                            log_entry_metadata(&metadata, &short_desc, level_desc, &event_xml),
                        )
                        .with_parent(artifact.id);

                        let timeline_artifact = Artifact::new(
                            artifact.case_id,
                            ArtifactType::TimelineEvent,
                            None,
                            timeline_metadata(&metadata, self.id(), &short_desc, level_desc),
                        )
                        .with_parent(log_entry_artifact.id);

                        produced_artifacts.push(log_entry_artifact);
                        produced_artifacts.push(timeline_artifact);
                    }
                    Err(e) => {
                        chunk_lost_something = true;
                        error_count += 1;
                        warn!(
                            "Failed to parse EVTX event XML from artifact {}: {}",
                            artifact.id, e
                        );
                        debug!("Problematic XML: {}", event_xml);
                    }
                }
            }
            live.note_chunk(chunk_offset, !chunk_lost_something, live_ids);
        }

        // The upstream walk stops at `(size - 4096) / 65536` whole chunks: a
        // chunk cut short by the end of the file fails its read and is taken
        // for the end of the log, so its records were lost with nothing said
        // (`HUNT-162`). Counted here, on this walk's own status record, and
        // left out of `live` so the recovery pass reads what survives of it.
        // Not looked for after an abort: the rest of the file is unread
        // anyway, and the abort already says so.
        let truncated_tail = if walk_aborted {
            None
        } else {
            truncated_tail_chunk(data_source.as_ref())
        };
        if let Some((offset, present)) = truncated_tail {
            warn!(
                "EVTX artifact {} ends {} bytes into the chunk at offset {}; the intact walk \
                 cannot read a partial chunk, so its records are left to the recovery pass",
                artifact.id, present, offset
            );
        }

        info!(
            "EVTX parsing complete for artifact {}: {} events parsed from {} chunk(s); \
             {} record error(s), {} unreadable chunk(s), {} chunk(s) faulted mid-decode \
             ({} of them partially recovered), walk aborted: {}",
            artifact.id,
            event_count,
            chunks_read,
            error_count,
            chunks_unreadable,
            chunk_panics,
            partial_chunks,
            walk_aborted
        );

        // Records the parser could not decode are events that happened on the
        // machine and are missing from this case. An examiner arguing that a
        // logon or a service start never occurred must be able to see that some
        // records were unreadable; a log line in a worker they never see is not
        // that. A skipped chunk is the same loss on a coarser grain — up to a
        // chunk's worth of events gone — so it is disclosed the same way and
        // never silently. Emitted only when something was actually lost.
        if error_count > 0
            || chunk_panics > 0
            || chunks_unreadable > 0
            || walk_aborted
            || truncated_tail.is_some()
        {
            produced_artifacts.push(parse_status_artifact(
                artifact.case_id,
                artifact.id,
                EvtxParseTally {
                    events_parsed: event_count,
                    records_failed: error_count,
                    chunks_skipped: chunk_panics,
                    chunks_unreadable,
                    chunks_read,
                    partial_chunks,
                    walk_aborted,
                    truncated_tail,
                },
            ));
        }

        Ok(())
    }
}

/// Size of the `ElfFile` header, and of every chunk that follows it.
const EVTX_FILE_HEADER_SIZE: u64 = 4096;
const EVTX_CHUNK_SIZE: u64 = 65_536;

/// The chunk the file ends inside, as `(offset, bytes present)`, when the
/// bytes past the last whole chunk open with the `ElfChnk\0` magic.
///
/// The upstream parser counts `(size - 4096) / 65536` chunks and treats a
/// failed read at or past that number as the end of the log, so a partial
/// chunk at the end of a file is never read and never reported. Only a tail
/// that begins with the chunk magic is counted: zero padding or other bytes
/// after the last chunk are not a lost chunk, and the recovery pass scans
/// them for loose records regardless.
pub(crate) fn truncated_tail_chunk(
    source: &dyn seance_core::data_source::DataSource,
) -> Option<(u64, u64)> {
    let size = source.size();
    let chunk_bytes = size.checked_sub(EVTX_FILE_HEADER_SIZE)?;
    let whole = chunk_bytes / EVTX_CHUNK_SIZE;
    let present = chunk_bytes % EVTX_CHUNK_SIZE;
    let offset = EVTX_FILE_HEADER_SIZE + whole * EVTX_CHUNK_SIZE;
    let mut magic = [0u8; 8];
    if present < magic.len() as u64 {
        return None;
    }
    let mut read = 0usize;
    while read < magic.len() {
        match source.read_at(offset + read as u64, &mut magic[read..]) {
            Ok(0) | Err(_) => return None,
            Ok(n) => read += n,
        }
    }
    (&magic == b"ElfChnk\0").then_some((offset, present))
}

/// The sentence an examiner is shown when a record's identifiers would not
/// decode, or `None` when both decoded.
///
/// Forensic meaning: this parser used to write 0 for an EventID it could not
/// read, and 0 is a value Windows itself logs. The invented ID was therefore
/// indistinguishable from a real one -- a filter for a given event ID, or a
/// count of how often one appears, silently included records whose ID was never
/// established. The record is still emitted, because an event that happened and
/// is missing from the case is the worse error; it is emitted saying which
/// identifier is unknown.
fn unreadable_id_detail(event_id: Option<u32>, event_record_id: Option<u64>) -> Option<String> {
    let unreadable: Vec<&str> = [
        event_id.is_none().then_some("EventID"),
        event_record_id.is_none().then_some("EventRecordID"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if unreadable.is_empty() {
        return None;
    }
    Some(format!(
        "{} could not be read from this record and is reported as null, not as 0: 0 is \
         itself a valid Windows identifier, so a record described as event 0 would read \
         as one the machine actually logged",
        unreadable.join(" and ")
    ))
}

/// Stamp the standard incompleteness pair on a record whose identifiers would
/// not decode.
///
/// `content_incomplete` / `content_incomplete_reason` are the keys the API,
/// export and frontend honesty paths read; a flag private to this plugin would
/// leave the record presenting as complete everywhere except here. The raw text
/// travels with it so the unreadable value is preserved rather than discarded.
fn stamp_unreadable_ids(target: &mut serde_json::Value, metadata: &EventMetadata) {
    let Some(detail) = unreadable_id_detail(metadata.event_id, metadata.event_record_id) else {
        return;
    };
    target["content_incomplete"] = json!(true);
    target["content_incomplete_reason"] = json!(IncompleteReason::UnresolvedStructure.as_str());
    target["content_incomplete_detail"] = json!(detail);
    if let Some(raw) = &metadata.event_id_raw {
        target["event_id_raw"] = json!(raw);
    }
    if let Some(raw) = &metadata.event_record_id_raw {
        target["event_record_id_raw"] = json!(raw);
    }
}

/// Build the `EvtxLogEntry` metadata for one decoded record.
///
/// Split out of `process` so the honesty contract -- an identifier that would
/// not decode leaves `event_id` null AND carries the incompleteness pair,
/// instead of reading as event 0 -- can be exercised directly, the way
/// [`parse_status_artifact`] is. Reaching it through `process` would need an
/// EVTX binary crafted to hold a malformed EventID.
fn log_entry_metadata(
    metadata: &EventMetadata,
    short_desc: &str,
    level_desc: &str,
    event_xml: &str,
) -> serde_json::Value {
    let mut entry = json!({
        "type": "EvtxLogEntry",
        "event_id": metadata.event_id,
        "event_record_id": metadata.event_record_id,
        "timestamp": metadata.timestamp,
        "timestamp_subsec_nanos": metadata.timestamp_subsec_nanos,
        "timestamp_utc": metadata.timestamp_utc,
        "computer_name": metadata.computer_name,
        "provider_name": metadata.provider_name,
        "channel": metadata.channel,
        "level": metadata.level,
        "level_description": level_desc,
        "task": metadata.task,
        "keywords": metadata.keywords,
        "user_sid": metadata.user_sid,
        "event_data": metadata.event_data,
        "short_desc": short_desc,
        "full_event_xml": event_xml,
    });
    stamp_unreadable_ids(&mut entry, metadata);
    stamp_xml_findings(&mut entry, metadata);
    entry
}

/// Copy the bounded reader's findings onto a record.
///
/// A record whose attributes were cut short by the cap, or which carried
/// duplicate or unparseable attribute names, says so on its own metadata. The
/// alternative is a record that reads as a faithful rendering of the event when
/// part of it was refused -- which in a report is a statement about the
/// evidence that is not true.
fn stamp_xml_findings(entry: &mut serde_json::Value, metadata: &EventMetadata) {
    let Some(object) = entry.as_object_mut() else {
        return;
    };
    for (key, value) in &metadata.xml_findings {
        object.insert((*key).to_string(), value.clone());
    }
}

/// Build the timeline event metadata for one decoded record.
fn timeline_metadata(
    metadata: &EventMetadata,
    source_module: &str,
    short_desc: &str,
    level_desc: &str,
) -> serde_json::Value {
    let mut full_details = json!({
        "event_id": metadata.event_id,
        "event_record_id": metadata.event_record_id,
        "provider": metadata.provider_name,
        "channel": metadata.channel,
        "level": level_desc,
        "computer": metadata.computer_name,
        "user_sid": metadata.user_sid,
    });
    // The insert keeps only the timeline_events columns, so a flag set beside
    // `full_details` would be dropped on the way to the database. The timeline
    // is where an unreadable EventID did the most damage -- it is read as a
    // sequence of things the machine did -- so the marker goes inside the
    // document that survives.
    stamp_unreadable_ids(&mut full_details, metadata);
    json!({
        // RFC 3339 with sub-second precision: an integer here would be stored
        // with zero nanoseconds, collapsing every event in a second onto one
        // indistinguishable instant.
        "timestamp": metadata.timestamp_utc,
        "timestamp_desc": "EventTime",
        "source_module": source_module,
        "short_desc": format!("{} on {}", short_desc, metadata.computer_name),
        "full_details": full_details.to_string(),
    })
}

/// Build the examiner-facing record that says some events in this log were
/// never decoded.
///
/// Forensic meaning: `events_parsed` alone cannot distinguish a quiet machine
/// from a log this parser could only partly read. `records_failed` is the count
/// of events that exist in the evidence but not in the case.
/// What one EVTX parse recovered and, in each of its distinct grains, what it
/// lost. Grouped rather than passed positionally because the grains are easy to
/// confuse and confusing them is the defect this record exists to prevent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EvtxParseTally {
    pub events_parsed: u64,
    /// EXACT, per record.
    pub records_failed: u64,
    /// Chunks abandoned after the decoder faulted mid-record.
    pub chunks_skipped: u64,
    /// Chunks whose header or body would not read at all.
    pub chunks_unreadable: u64,
    /// Chunks whose header was read, faulted or not.
    pub chunks_read: u64,
    /// Faulted chunks from which some records were still recovered.
    pub partial_chunks: u64,
    /// The walk stopped before the end of the file, so every count is a floor.
    pub walk_aborted: bool,
    /// The file ends inside a chunk the walk could therefore not read:
    /// `(chunk offset, bytes of it present)`.
    pub truncated_tail: Option<(u64, u64)>,
}

fn parse_status_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    tally: EvtxParseTally,
) -> Artifact {
    let EvtxParseTally {
        events_parsed,
        records_failed,
        chunks_skipped,
        chunks_unreadable,
        chunks_read,
        partial_chunks,
        walk_aborted,
        truncated_tail,
    } = tally;
    // Each grain of loss is named separately, because they are different sizes
    // and an examiner arguing from an absence needs to know which one they are
    // looking at. `records_failed` is EXACT and per record. The chunk figures
    // are each up to a chunk's worth of events. `walk_aborted` is the largest:
    // the remainder of the FILE after the abort point was never read, so every
    // count here is a floor rather than a total.
    let mut reasons: Vec<&str> = Vec::new();
    if walk_aborted {
        reasons.push("chunk_walk_aborted_after_decode_panic");
    }
    if records_failed > 0 {
        reasons.push("records_failed_to_parse");
    }
    if chunks_skipped > 0 {
        reasons.push("chunks_skipped_after_decode_panic");
    }
    if chunks_unreadable > 0 {
        reasons.push("chunks_unreadable");
    }
    if truncated_tail.is_some() {
        reasons.push("chunk_truncated_at_end_of_file");
    }
    let reason = reasons.join(",");

    let message = if walk_aborted {
        format!(
            "This event log was NOT read to the end. A chunk header faulted while decoding after \
             {chunks_read} chunk(s), leaving the parser at an unknown offset, so the remainder of \
             the file was never examined. Every count on this record is therefore a FLOOR: the \
             events it reports as lost are those seen so far, not the total. The absence of an \
             event from this case is not evidence that it was never logged."
        )
    } else if records_failed > 0 || chunks_skipped > 0 || chunks_unreadable > 0 {
        "Some of this event log could not be decoded: the events it held are absent from this \
         case and their absence is not evidence that nothing was logged. 'records_failed' is an \
         exact count of individually undecodable records; 'chunks_unreadable' and \
         'chunks_skipped' each count 64 KiB chunks, any one of which may have held many events."
            .to_string()
    } else {
        // The only loss is a chunk the file ends inside, described below.
        "Every whole chunk of this event log was read, but not every chunk.".to_string()
    };
    // A chunk cut short by the end of the file is a different loss from a
    // chunk that would not decode: its bytes were never handed to the
    // decoder at all. Its records are not necessarily gone -- the recovery
    // pass reads what survives -- so the message says where they went.
    let message = match truncated_tail {
        Some((offset, present)) => format!(
            "{message} The file ends {present} bytes into the chunk at offset {offset} (of \
             {EVTX_CHUNK_SIZE}); a partial chunk cannot be read by this walk, so none of its \
             events is among the events parsed here. Its surviving records are read by the \
             recovery pass and appear as EvtxRecoveredLogEntry, with the chunk listed on this \
             log's EvtxRecoveryStatus; a record the cut runs through is partial."
        ),
        None => message,
    };

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "EvtxParseStatus",
            "record_type": "evtx_parse_status",
            "name": "EVTX log (partially parsed)",
            "content_incomplete": true,
            "content_incomplete_reason": reason,
            // What is short here is a LISTING of events, so it carries the
            // inventory flag as well as the content pair. Without it a
            // consumer that asks "is this event list complete?" -- rather than
            // "is this record's content complete?" -- reads a partly decoded
            // log as the whole log.
            "inventory_incomplete": true,
            "events_parsed": events_parsed,
            // Exact, per record.
            "records_failed": records_failed,
            // Chunk-sized losses. Each may have held many events, so these are
            // counts of CHUNKS, never of events.
            "chunks_skipped": chunks_skipped,
            "chunks_unreadable": chunks_unreadable,
            "chunks_partially_recovered": partial_chunks,
            "chunks_read": chunks_read,
            // The largest loss of all, and the one that makes every other
            // figure a floor: the file was not read to its end.
            "walk_aborted": walk_aborted,
            "counts_are_floor": walk_aborted,
            // A chunk the file ends inside: never read by this walk, and its
            // records left to the recovery pass.
            "chunks_truncated_at_eof": u64::from(truncated_tail.is_some()),
            "truncated_chunk_offset": truncated_tail.map(|(offset, _)| offset),
            "truncated_chunk_bytes_present": truncated_tail.map(|(_, present)| present),
            "message": message,
        }),
    )
    .with_parent(parent_id)
}

/// Whether the recovery pass produced anything an examiner must see.
///
/// On an intact file every carved chunk is normally one the intact walk
/// decoded, so a status record saying "nothing recovered" would be noise on
/// every log in the case. It is emitted when a record was recovered, when
/// something was found and not decoded, when a bound was hit, and always on an
/// input that had no file header -- there the recovery pass IS the parse, and
/// "looked, found nothing" is a finding.
fn recovery_has_something_to_say(recovered: &Recovery, intact: bool) -> bool {
    let t = &recovered.tally;
    !intact
        || !recovered.records.is_empty()
        || t.chunks_found > t.chunks_live_skipped
        || t.loose_records_found > 0
        || t.short_read
        || t.scan_bound_hit
        || t.chunks_bound_hit
        || t.records_bound_hit
        || t.template_pool_bound_hit
}

/// Build the artifacts for one recovered record: the `EvtxRecoveredLogEntry`
/// and, when the record header's time is plausible, a timeline event.
///
/// The entry is a DIFFERENT TYPE from a live `EvtxLogEntry`, and carries a
/// `recovery_source` a live record never has. An examiner filtering a case by
/// type cannot pick up a recovered event as a live one, and a report that
/// quotes one quotes its provenance with it: which chunk, what state its
/// header was in, whether its checksums held, whether its template was its
/// own, and which substitutions -- by index -- could not be bound.
fn recovered_record_artifacts(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    source_module: &str,
    record: &RecoveredRecord,
) -> (Artifact, Option<Artifact>) {
    let parsed = record
        .xml
        .as_deref()
        .and_then(|xml| EvtxParser::parse_event_xml(xml).ok());
    let (timestamp, subsec, timestamp_utc) = match record.timestamp {
        Some(ts) => {
            let (secs, nanos, utc) = record_times(ts);
            (json!(secs), json!(nanos), json!(utc))
        }
        None => (json!(null), json!(null), json!(null)),
    };
    let short_desc = match &parsed {
        Some(m) => EvtxParser::get_event_description(m.event_id, &m.provider_name, &m.channel),
        None => format!(
            "EVTX record {} (recovered, content unavailable)",
            record.event_record_id
        ),
    };
    let level_desc = EvtxParser::get_level_description(parsed.as_ref().and_then(|m| m.level));
    let partial = record.is_partial();

    let mut entry = json!({
        "type": "EvtxRecoveredLogEntry",
        "record_type": "evtx_recovered_record",
        "recovered": true,
        "recovery_source": record.source.as_str(),
        "record_offset": record.offset,
        "record_size": record.size,
        "record_trailer_valid": record.trailer_valid,
        "record_header_event_record_id": record.event_record_id,
        "chunk_offset": record.chunk_offset,
        "chunk_header": record.chunk_header.as_str(),
        "chunk_header_checksum": record.header_checksum.as_str(),
        "chunk_data_checksum": record.data_checksum.as_str(),
        "chunk_truncated": record.chunk_truncated,
        "template_id": record.template_id.map(|id| format!("{id:#010x}")),
        "substitution_count": record.substitution_count,
        "timestamp": timestamp,
        "timestamp_subsec_nanos": subsec,
        "timestamp_utc": timestamp_utc,
        "rendered_with_borrowed_template": record.borrowed_template.is_some(),
        "partial": partial,
        "incomplete_substitutions": record
            .incomplete
            .iter()
            .map(|i| json!({
                "index": i.index,
                "position": i.position,
                "reason": i.reason,
                "values_without_names": i.values_without_names,
            }))
            .collect::<Vec<_>>(),
        "short_desc": short_desc,
        "level_description": level_desc,
        "full_event_xml": record.xml,
        "own_decode_failure": record.own_decode_failure,
        "record_id_also_read_live": record.also_read_live,
        "recovery_note": recovery_note(record),
    });
    // A slack record's own checksum fields are `not_applicable`: the chunk's
    // CRCs stop at its free-space offset and the record was read from past
    // it. The chunk's real states are kept, under names that say whose they
    // are, so a reader cannot take `valid` for a verification of these bytes.
    if let Some((header, data)) = record.containing_chunk_checksums {
        entry["containing_chunk_header_checksum"] = json!(header.as_str());
        entry["containing_chunk_data_checksum"] = json!(data.as_str());
        entry["chunk_checksum_note"] = json!(format!(
            "This record was read from the chunk's slack, past its free-space offset. The \
             chunk's data checksum covers bytes 512 to the free-space offset and its header \
             checksum covers the header, so neither covers this record's bytes, which were \
             decoded under a synthesised header: both are reported as not_applicable. The \
             containing chunk's own states (header {}, data {}) say only that the chunk's \
             live region is intact.",
            header.as_str(),
            data.as_str()
        ));
    }
    if record.timestamp.is_none() {
        entry["timestamp_unreadable_reason"] = json!(
            "the record header's FILETIME is outside any plausible event range and is not \
             rendered as a date"
        );
    }
    if let Some(b) = &record.borrowed_template {
        entry["borrowed_template"] = json!({
            "template_id": format!("{:#010x}", b.template_id),
            "guid": b.guid,
            "text_hash": b.text_hash,
            "from_chunk_offset": b.from_chunk_offset,
            "candidates": b.candidates,
            "ambiguous": b.candidates > 1,
            "guid_confirmed": b.guid_confirmed,
        });
    }
    match &parsed {
        Some(m) => {
            entry["event_id"] = json!(m.event_id);
            entry["event_record_id"] = json!(m.event_record_id.unwrap_or(record.event_record_id));
            entry["computer_name"] = json!(m.computer_name);
            entry["provider_name"] = json!(m.provider_name);
            entry["channel"] = json!(m.channel);
            entry["level"] = json!(m.level);
            entry["task"] = json!(m.task);
            entry["keywords"] = json!(m.keywords);
            entry["user_sid"] = json!(m.user_sid);
            entry["event_data"] = json!(m.event_data);
            if let Some(raw) = &m.event_id_raw {
                entry["event_id_raw"] = json!(raw);
            }
            stamp_xml_findings(&mut entry, m);
        }
        None => {
            entry["event_id"] = json!(null);
            entry["event_record_id"] = json!(record.event_record_id);
        }
    }
    if partial {
        let detail = match &record.failure {
            Some(why) => format!("No content could be rendered for this record: {why}"),
            None => format!(
                "{} substitution(s) could not be bound (indices {}); the XML holds what did \
                 bind and a SeanceIncomplete marker at each text position that did not",
                record.incomplete.len(),
                record
                    .incomplete
                    .iter()
                    .map(|i| i.index.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        entry["content_incomplete"] = json!(true);
        entry["content_incomplete_reason"] = json!(IncompleteReason::UnresolvedStructure.as_str());
        entry["content_incomplete_detail"] = json!(detail);
    }

    let entry_artifact =
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, entry).with_parent(parent_id);

    let timeline = record.timestamp.map(|ts| {
        let (_, _, utc) = record_times(ts);
        let computer = parsed
            .as_ref()
            .map(|m| m.computer_name.as_str())
            .unwrap_or("unknown computer");
        let full_details = json!({
            "recovered": true,
            "recovery_source": record.source.as_str(),
            "partial": partial,
            "rendered_with_borrowed_template": record.borrowed_template.is_some(),
            "event_id": parsed.as_ref().and_then(|m| m.event_id),
            "event_record_id": record.event_record_id,
            "provider": parsed.as_ref().map(|m| m.provider_name.clone()),
            "channel": parsed.as_ref().map(|m| m.channel.clone()),
            "computer": parsed.as_ref().map(|m| m.computer_name.clone()),
            "chunk_offset": record.chunk_offset,
            "record_offset": record.offset,
        });
        Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": utc,
                "timestamp_desc": "EventTime (recovered)",
                "source_module": source_module,
                "short_desc": format!("{short_desc} on {computer} [recovered]"),
                "full_details": full_details.to_string(),
            }),
        )
        .with_parent(entry_artifact.id)
    });

    (entry_artifact, timeline)
}

/// The sentence that says where a recovered record came from and how far it
/// can be trusted.
fn recovery_note(record: &RecoveredRecord) -> String {
    let mut note = match record.source {
        recovery::RecoverySource::CarvedChunk => format!(
            "Recovered from a carved ElfChnk chunk at offset {} that the intact parser did \
             not decode; the chunk header checksum was {} and the data checksum {}.",
            record.chunk_offset.unwrap_or(0),
            record.header_checksum.as_str(),
            record.data_checksum.as_str()
        ),
        recovery::RecoverySource::ChunkSlack => format!(
            "Recovered from the slack of the chunk at offset {}, past its free-space offset: \
             a record from an earlier use of the chunk. Its references into the chunk point \
             at bytes since rewritten, so those were refused rather than read.",
            record.chunk_offset.unwrap_or(0)
        ),
        recovery::RecoverySource::LooseRecord => match record.chunk_offset {
            Some(base) => format!(
                "Recovered outside any carved chunk; its chunk header is gone. It was decoded \
                 against an inferred 64 KiB window at offset {base} under a synthesised header."
            ),
            None => "Recovered outside any carved chunk, and no chunk window could be inferred \
                     for it; only its header facts are known."
                .to_string(),
        },
    };
    if let Some(b) = &record.borrowed_template {
        note.push_str(&format!(
            " Rendered with template {:#010x} borrowed from the chunk at offset {}{}.",
            b.template_id,
            b.from_chunk_offset,
            if b.candidates > 1 {
                format!(
                    " (one of {} distinct renderings pooled under that id)",
                    b.candidates
                )
            } else {
                String::new()
            }
        ));
    }
    if !record.incomplete.is_empty() {
        note.push_str(&format!(
            " {} substitution(s) could not be bound; see incomplete_substitutions.",
            record.incomplete.len()
        ));
    }
    note
}

/// The examiner-facing record for one recovery pass: what was scanned, what
/// was found, what came back, and every bound with the number it stopped at.
fn recovery_status_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    recovered: &Recovery,
) -> Artifact {
    let t = &recovered.tally;
    let l = &recovered.limits;
    let mut reasons: Vec<&str> = Vec::new();
    if t.scan_bound_hit || t.chunks_bound_hit || t.records_bound_hit || t.template_pool_bound_hit {
        reasons.push(IncompleteReason::CapReached.as_str());
    }
    if t.short_read {
        reasons.push(IncompleteReason::ShortRead.as_str());
    }
    if t.records_partial > 0 || t.chunks_unopenable > 0 || t.loose_records_unlocatable > 0 {
        reasons.push(IncompleteReason::UnresolvedStructure.as_str());
    }
    // A short read is a bound the source imposed rather than one the code
    // chose, and it leaves the inventory short the same way: bytes past it
    // were not scanned, so every count is a floor.
    let bounded = t.scan_bound_hit || t.chunks_bound_hit || t.records_bound_hit || t.short_read;

    let mut message = format!(
        "EVTX recovery scanned {} of the {} byte(s) the input declared and found {} ElfChnk chunk signature(s): {} with valid \
         checksums, {} with failed checksums, {} without a checksum, {} whose checksum covers \
         bytes that are not there, {} truncated, {} already read live by the intact parser. {} record(s) were recovered whole, {} partially \
         ({} with no content at all), {} rendered with a template borrowed from another chunk; \
         {} loose record(s) were found outside any chunk in {} inferred window(s), {} of them \
         with no window that could be inferred. {} template(s) were pooled across chunks.",
        t.bytes_scanned,
        t.bytes_declared,
        t.chunks_found,
        t.chunks_checksum_valid,
        t.chunks_checksum_failed,
        t.chunks_checksum_absent,
        t.chunks_checksum_unverifiable,
        t.chunks_truncated,
        t.chunks_live_skipped,
        t.records_recovered,
        t.records_partial,
        t.records_header_only,
        t.records_borrowed_template,
        t.loose_records_found,
        t.loose_windows,
        t.loose_records_unlocatable,
        t.templates_pooled,
    );
    if t.scan_bound_hit {
        message.push_str(&format!(
            " The signature scan STOPPED at its bound of {} byte(s); the remainder of the input \
             was not examined.",
            l.scan_bytes
        ));
    }
    if t.short_read {
        message.push_str(&format!(
            " The input declared {} byte(s) but the read ran out after {}; the {} byte(s) past \
             the read were NOT scanned and nothing is known about them (short_read).",
            t.bytes_declared,
            t.bytes_scanned,
            t.bytes_declared.saturating_sub(t.bytes_scanned)
        ));
    }
    if t.chunks_bound_hit {
        message.push_str(&format!(
            " Chunk recovery STOPPED at its bound of {} chunk(s); further signatures were not \
             followed.",
            l.chunks
        ));
    }
    if t.records_bound_hit {
        message.push_str(&format!(
            " Record recovery STOPPED at its bound of {} record(s); further records were not \
             decoded.",
            l.records
        ));
    }
    if t.template_pool_bound_hit {
        message.push_str(&format!(
            " The template pool reached its bound of {} template(s); later templates were \
             not pooled and records needing them could not be revived.",
            l.pooled_templates
        ));
    }
    if recovered.chunks.is_empty() && t.chunks_not_listed == 0 {
        message.push_str(" No chunk had anything to disclose beyond the counts above.");
    } else {
        message.push_str(&format!(
            " {} chunk(s) of note (a checksum that did not verify, a truncation, discarded \
             tables, a failure to open, or records recovered) are listed by offset under \
             chunk_listing.",
            recovered.chunks.len()
        ));
    }
    if t.chunk_listing_bound_hit {
        message.push_str(&format!(
            " The listing STOPPED at its bound of {} chunk(s); {} chunk(s) of note are counted \
             above but not listed.",
            l.listed_chunks, t.chunks_not_listed
        ));
    }
    message.push_str(
        " Recovered records are of type EvtxRecoveredLogEntry and are never presented as \
         live events; a partial record names each substitution index it could not bind.",
    );

    let chunk_listing: Vec<serde_json::Value> = recovered
        .chunks
        .iter()
        .map(|c| {
            json!({
                "offset": c.offset,
                "header_checksum": c.header_checksum.as_str(),
                "data_checksum": c.data_checksum.as_str(),
                "truncated": c.truncated,
                "chunk_header": c.chunk_header.as_str(),
                "unopenable": c.unopenable,
                "read_live_whole": c.read_live_whole,
                "records_recovered": c.records_recovered,
                "slack_records_recovered": c.slack_records_recovered,
            })
        })
        .collect();

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "EvtxRecoveryStatus",
            "record_type": "evtx_recovery_status",
            "name": "EVTX fragment recovery",
            "bytes_declared": t.bytes_declared,
            "bytes_scanned": t.bytes_scanned,
            "scan_bound_hit": t.scan_bound_hit,
            "short_read": t.short_read,
            "chunks_found": t.chunks_found,
            "chunks_checksum_valid": t.chunks_checksum_valid,
            "chunks_checksum_failed": t.chunks_checksum_failed,
            "chunks_checksum_absent": t.chunks_checksum_absent,
            "chunks_checksum_unverifiable": t.chunks_checksum_unverifiable,
            "chunks_truncated": t.chunks_truncated,
            "chunks_live_skipped": t.chunks_live_skipped,
            "chunks_nested_skipped": t.chunks_nested_skipped,
            "chunks_tables_discarded": t.chunks_tables_discarded,
            "chunks_unopenable": t.chunks_unopenable,
            "chunks_bound_hit": t.chunks_bound_hit,
            "records_recovered": t.records_recovered,
            "records_partial": t.records_partial,
            "records_header_only": t.records_header_only,
            "records_borrowed_template": t.records_borrowed_template,
            "records_already_live": t.records_already_live,
            "records_bound_hit": t.records_bound_hit,
            "loose_records_found": t.loose_records_found,
            "loose_windows": t.loose_windows,
            "loose_records_unlocatable": t.loose_records_unlocatable,
            "templates_pooled": t.templates_pooled,
            "template_pool_bound_hit": t.template_pool_bound_hit,
            "limits": {
                "max_scan_bytes": l.scan_bytes,
                "max_chunks": l.chunks,
                "max_records": l.records,
                "max_pooled_templates": l.pooled_templates,
                "max_listed_chunks": l.listed_chunks,
            },
            // Every chunk with something to say beyond the counts, named by
            // the offset it was carved at, up to the bound; a chunk that
            // verified whole, was read live in full and yielded nothing is
            // in the counts only.
            "chunk_listing": {
                "criterion": "checksum not valid, truncated, tables discarded, unopenable, or records recovered",
                "bound": l.listed_chunks,
                "bound_hit": t.chunk_listing_bound_hit,
                "listed": chunk_listing.len(),
                "omitted": t.chunks_not_listed,
                "chunks": chunk_listing,
            },
            // A bound that was hit means the listing of recovered events is
            // short; a partial record means content is short. Both flags are
            // set so a consumer asking either question gets the answer.
            "inventory_incomplete": bounded,
            "content_incomplete": !reasons.is_empty(),
            "content_incomplete_reason": if reasons.is_empty() { json!(null) } else { json!(reasons.join(",")) },
            "counts_are_floor": bounded,
            "message": message,
        }),
    )
    .with_parent(parent_id)
}

#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod tests;
