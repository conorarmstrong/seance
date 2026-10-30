//! Recovery of records the intact parser cannot read, against real logs.
//!
//! The corpus-gated tests damage a REAL Windows System log (plaso's
//! `System2.evtx`: 200,000 bytes, two whole chunks and a third cut short by
//! whoever copied it) in the ways evidence is damaged in practice, and grade
//! what comes back against what the intact parser reads from the pristine
//! file. The ungated tests pin the contracts that need no corpus: the record
//! type, the bound disclosures, the sentinel splitter and the FILETIME range.

use super::recovery::*;
use super::tests::MockEvtxSource;
use super::*;
use seance_core::data_source::DataSource;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

const CORPUS: &str = "SEANCE_EVTX_CORPUS";
const FILE_HEADER: usize = 4096;
const CHUNK: usize = 65_536;

fn corpus_bytes(name: &str) -> Option<Vec<u8>> {
    let path = seance_core::test_support::corpus::file(CORPUS, name)?;
    Some(std::fs::read(&path).expect("corpus file reads"))
}

fn run(data: Vec<u8>, name: &str) -> Vec<Artifact> {
    let source: Arc<dyn DataSource> = Arc::new(MockEvtxSource::new(data));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        json!({ "name": name }),
    );
    EvtxParser.process(&artifact).expect("process returns Ok")
}

fn of_type<'a>(artifacts: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    artifacts
        .iter()
        .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some(ty))
        .collect()
}

/// The forensic content of one event, in the form both a live and a
/// recovered record can be reduced to.
#[derive(Debug, PartialEq, Eq, Clone)]
struct EventFacts {
    event_id: Option<u64>,
    computer: String,
    provider: String,
    channel: String,
    level: Option<u64>,
    task: Option<u64>,
    keywords: Option<String>,
    user_sid: Option<String>,
    event_data: BTreeMap<String, String>,
}

fn facts(a: &Artifact) -> EventFacts {
    let m = &a.metadata;
    EventFacts {
        event_id: m["event_id"].as_u64(),
        computer: m["computer_name"].as_str().unwrap_or("").to_string(),
        provider: m["provider_name"].as_str().unwrap_or("").to_string(),
        channel: m["channel"].as_str().unwrap_or("").to_string(),
        level: m["level"].as_u64(),
        task: m["task"].as_u64(),
        keywords: m["keywords"].as_str().map(str::to_string),
        user_sid: m["user_sid"].as_str().map(str::to_string),
        event_data: m["event_data"]
            .as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn by_record_id(artifacts: &[&Artifact]) -> BTreeMap<u64, EventFacts> {
    artifacts
        .iter()
        .filter_map(|a| {
            a.metadata["event_record_id"]
                .as_u64()
                .map(|id| (id, facts(a)))
        })
        .collect()
}

/// Every event the intact parser reads from the pristine file, keyed by
/// record id: the answer key for each damaged copy.
fn live_answer_key(pristine: &[u8]) -> BTreeMap<u64, EventFacts> {
    let out = run(pristine.to_vec(), "System2.evtx");
    by_record_id(&of_type(&out, "EvtxLogEntry"))
}

#[test]
fn a_log_whose_file_header_was_zeroed_gives_back_every_record_the_intact_parser_read() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let key = live_answer_key(&pristine);
    assert_eq!(
        key.len(),
        194,
        "the pristine file's two whole chunks hold 194 records"
    );

    let mut damaged = pristine.clone();
    damaged[..FILE_HEADER].fill(0);
    let out = run(damaged, "System2.evtx");

    assert!(
        of_type(&out, "EvtxLogEntry").is_empty(),
        "with no file header nothing can be called a live record"
    );
    let recovered = of_type(&out, "EvtxRecoveredLogEntry");
    let got = by_record_id(&recovered);
    for (id, want) in &key {
        let have = got
            .get(id)
            .unwrap_or_else(|| panic!("record {id} was read live but not recovered"));
        assert_eq!(have, want, "record {id} recovered with different content");
    }
    // The third chunk is cut short; the intact parser never reads it at all.
    assert!(
        got.len() >= key.len() + 88,
        "recovery must also reach the truncated third chunk: got {} records, live key {}",
        got.len(),
        key.len()
    );
    for a in &recovered {
        assert_eq!(a.metadata["recovery_source"], "carved_chunk");
        assert_eq!(a.metadata["recovered"], true);
        assert_eq!(a.metadata["chunk_header"], "present");
    }

    let status = of_type(&out, "EvtxRecoveryStatus");
    assert_eq!(status.len(), 1);
    let s = &status[0].metadata;
    assert_eq!(s["chunks_found"], 3);
    assert_eq!(s["chunks_checksum_valid"], 2);
    assert_eq!(s["chunks_checksum_failed"], 0);
    assert_eq!(
        s["chunks_checksum_unverifiable"], 1,
        "the cut chunk's data checksum covers bytes that are not there: neither valid nor failed"
    );
    assert_eq!(s["chunks_truncated"], 1);
    assert_eq!(
        s["records_recovered"].as_u64().unwrap() + s["records_partial"].as_u64().unwrap(),
        got.len() as u64
    );
}

#[test]
fn the_truncated_tail_chunk_the_intact_parser_drops_is_recovered_and_its_cut_record_is_partial() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let out = run(pristine, "System2.evtx");
    assert_eq!(of_type(&out, "EvtxLogEntry").len(), 194);

    let recovered = of_type(&out, "EvtxRecoveredLogEntry");
    // 89 records begin in the third chunk. The last (id 284) is cut at 360 of
    // its 616 bytes, so it can only ever be partial; and record 216, a 4739
    // domain-policy event, holds a value in its EventData that the upstream
    // decoder cannot read even when the chunk is whole (the intact parser
    // counts it under `records_failed`), so it comes back with its System
    // section and a marker where its EventData would be.
    let complete: Vec<_> = recovered
        .iter()
        .filter(|a| a.metadata["partial"] == false)
        .collect();
    let partial: Vec<_> = recovered
        .iter()
        .filter(|a| a.metadata["partial"] == true)
        .collect();
    assert_eq!(complete.len(), 88);
    assert_eq!(partial.len(), 2);
    let undecodable = partial
        .iter()
        .find(|a| a.metadata["record_header_event_record_id"] == 216)
        .expect("record 216 is recovered as partial, not dropped");
    assert!(
        undecodable.metadata["own_decode_failure"].is_string(),
        "a record rendered from the pool says why its own decode failed"
    );
    let cut = partial
        .iter()
        .find(|a| a.metadata["record_header_event_record_id"] == 284)
        .expect("the cut record is recovered as partial, not dropped");
    assert_eq!(cut.metadata["content_incomplete"], true);
    assert_eq!(cut.metadata["chunk_truncated"], true);
    assert_eq!(
        cut.metadata["chunk_data_checksum"],
        "unverifiable_truncated"
    );
    assert_eq!(cut.metadata["record_trailer_valid"], false);
    let incomplete = cut.metadata["incomplete_substitutions"]
        .as_array()
        .expect("a partial record lists what it lost");
    assert!(
        !incomplete.is_empty(),
        "the cut record must name the substitution indices it could not bind"
    );
    for entry in incomplete {
        assert!(
            entry["index"].is_u64(),
            "each loss names its index: {entry}"
        );
        assert!(
            entry["reason"].as_str().unwrap_or("").contains("ends"),
            "the reason says the record's bytes ran out: {entry}"
        );
    }
    let xml = cut.metadata["full_event_xml"]
        .as_str()
        .expect("what could be rendered is still emitted");
    assert!(
        xml.contains("<SeanceIncomplete substitution=\""),
        "the partial XML carries an explicit marker at the lost position: {xml}"
    );
    assert!(
        xml.contains("<EventRecordID>"),
        "the System section that did bind is present: {xml}"
    );
    for a in &recovered {
        assert_eq!(a.metadata["recovery_source"], "carved_chunk");
        assert_eq!(a.metadata["chunk_truncated"], true);
    }

    let s = &of_type(&out, "EvtxRecoveryStatus")[0].metadata;
    assert_eq!(s["chunks_found"], 3);
    assert_eq!(s["chunks_live_skipped"], 2);
    assert_eq!(s["chunks_truncated"], 1);
    assert_eq!(s["records_recovered"], 88);
    assert_eq!(s["records_partial"], 2);
    assert_eq!(s["records_already_live"], 0);
}

#[test]
fn a_chunk_whose_header_was_destroyed_yields_its_records_as_loose_records_in_an_inferred_window() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let key = live_answer_key(&pristine);
    let chunk1 = FILE_HEADER + CHUNK;

    let mut damaged = pristine.clone();
    damaged[..FILE_HEADER].fill(0);
    damaged[chunk1..chunk1 + 512].fill(0);
    let out = run(damaged, "System2.evtx");

    let recovered = of_type(&out, "EvtxRecoveredLogEntry");
    let loose: Vec<&Artifact> = recovered
        .iter()
        .copied()
        .filter(|a| a.metadata["recovery_source"] == "loose_record")
        .collect();
    assert_eq!(
        loose.len(),
        90,
        "all 90 records of the headerless chunk come back loose"
    );
    let got = by_record_id(&loose);
    for (id, want) in key.iter().filter(|(id, _)| (105..=194).contains(*id)) {
        let have = got
            .get(id)
            .unwrap_or_else(|| panic!("record {id} of the headerless chunk not recovered"));
        assert_eq!(have, want, "record {id} recovered with different content");
    }
    for a in &loose {
        assert_eq!(a.metadata["chunk_header"], "synthetic");
        assert_eq!(a.metadata["chunk_header_checksum"], "none");
        assert_eq!(a.metadata["chunk_offset"], chunk1 as u64);
    }

    let s = &of_type(&out, "EvtxRecoveryStatus")[0].metadata;
    assert_eq!(s["chunks_found"], 2, "only two chunk signatures survive");
    assert_eq!(s["loose_records_found"], 90);
    assert_eq!(s["loose_windows"], 1);
}

#[test]
fn a_record_whose_template_definition_is_corrupt_is_rendered_from_another_chunks_identical_template(
) {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let key = live_answer_key(&pristine);

    // Template 0x110ba5fa is defined inline by record 39 in chunk 0 (at chunk
    // offset 28454) and again by record 105 in chunk 1. Overwriting the
    // fragment header that opens the chunk-0 definition leaves every chunk-0
    // record that uses it without a readable template.
    let def = FILE_HEADER + 28454;
    let mut damaged = pristine.clone();
    assert_eq!(&damaged[def + 24..def + 28], &[0x0f, 0x01, 0x01, 0x00]);
    damaged[def + 24..def + 28].fill(0xff);
    let out = run(damaged, "System2.evtx");

    let live = by_record_id(&of_type(&out, "EvtxLogEntry"));
    assert!(
        !live.contains_key(&39),
        "record 39 cannot be read live once its template is gone"
    );
    let recovered = of_type(&out, "EvtxRecoveredLogEntry");
    // Chunk 0 only: the truncated third chunk contributes its own partial
    // records whatever is done to chunk 0.
    let borrowed: Vec<&Artifact> = recovered
        .iter()
        .copied()
        .filter(|a| {
            a.metadata["rendered_with_borrowed_template"] == true
                && a.metadata["chunk_offset"] == FILE_HEADER as u64
        })
        .collect();
    assert!(
        !borrowed.is_empty(),
        "the orphaned records are revived from the pool"
    );
    let got = by_record_id(&borrowed);
    assert!(got.contains_key(&39));
    for (id, have) in &got {
        assert_eq!(
            have,
            key.get(id)
                .expect("every borrowed record was live in the pristine file"),
            "record {id} rendered with a borrowed template differs from its live reading"
        );
        assert!(
            !live.contains_key(id),
            "record {id} was emitted both live and recovered"
        );
    }
    for a in &borrowed {
        let b = &a.metadata["borrowed_template"];
        assert_eq!(b["template_id"], "0x110ba5fa");
        assert_eq!(b["from_chunk_offset"], (FILE_HEADER + CHUNK) as u64);
        assert_eq!(b["guid_confirmed"], true);
        assert_eq!(b["ambiguous"], false);
        assert_eq!(a.metadata["partial"], false);
        assert_eq!(a.metadata["recovery_source"], "carved_chunk");
        assert!(a.metadata["own_decode_failure"]
            .as_str()
            .unwrap()
            .contains("template"));
    }

    let s = &of_type(&out, "EvtxRecoveryStatus")[0].metadata;
    assert!(s["records_borrowed_template"].as_u64().unwrap() >= borrowed.len() as u64);
    assert!(s["templates_pooled"].as_u64().unwrap() >= 5);
}

#[test]
fn slack_records_from_a_reused_chunk_come_back_with_their_names_poisoned_not_guessed() {
    let Some(pristine) = corpus_bytes("system.evtx") else {
        return;
    };
    let out = run(pristine, "system.evtx");
    let slack: Vec<_> = of_type(&out, "EvtxRecoveredLogEntry")
        .into_iter()
        .filter(|a| a.metadata["recovery_source"] == "chunk_slack")
        .collect();
    // Chunk 14 (offset 921600) has 35,272 bytes of slack holding 79 records
    // from an earlier use of the chunk, ids 1750..=1828.
    assert_eq!(slack.len(), 79);
    let ids: Vec<u64> = slack
        .iter()
        .map(|a| {
            a.metadata["record_header_event_record_id"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(ids[0], 1750);
    assert_eq!(*ids.last().unwrap(), 1828);
    for a in &slack {
        assert_eq!(a.metadata["chunk_offset"], 921_600u64);
        assert_eq!(
            a.metadata["rendered_with_borrowed_template"], true,
            "a stale record's own template reference points at rewritten bytes"
        );
        assert!(a.metadata["timestamp_utc"]
            .as_str()
            .unwrap()
            .starts_with("2017-"));
        // Whatever the current chunk holds at the offsets the stale record
        // names must not be presented as the record's content.
        let xml = a.metadata["full_event_xml"].as_str().unwrap();
        assert!(
            xml.contains("<EventRecordID>"),
            "the System section binds: {xml}"
        );
    }
    let s = &of_type(&out, "EvtxRecoveryStatus")[0].metadata;
    assert_eq!(s["chunks_found"], 15);
    assert_eq!(s["chunks_live_skipped"], 15);
}

#[test]
fn a_narrowed_chunk_bound_is_disclosed_with_the_number_it_stopped_at() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let source = MockEvtxSource::new(pristine);
    let limits = Limits {
        chunks: 1,
        ..Limits::default()
    };
    let r = recover_with_limits(&source, &LiveCoverage::default(), limits);
    assert!(r.tally.chunks_bound_hit);
    assert_eq!(r.tally.chunks_found, 1);
    let carved = r
        .records
        .iter()
        .filter(|rec| rec.source == RecoverySource::CarvedChunk)
        .count();
    assert_eq!(
        carved, 104,
        "the one chunk under the bound is still fully decoded"
    );
    // The chunks past the bound were never carved, so their records are met
    // by the loose-record scan instead and say so.
    assert!(
        r.records
            .iter()
            .filter(|rec| rec.source == RecoverySource::LooseRecord)
            .count()
            > 0
    );

    let status = recovery_status_artifact(Uuid::new_v4(), Uuid::new_v4(), &r);
    assert_eq!(status.metadata["chunks_bound_hit"], true);
    assert_eq!(status.metadata["limits"]["max_chunks"], 1);
    assert_eq!(status.metadata["inventory_incomplete"], true);
    assert!(status.metadata["content_incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("cap_reached"));
    assert!(status.metadata["message"]
        .as_str()
        .unwrap()
        .contains("1 chunk"));
}

#[test]
fn a_narrowed_record_bound_stops_the_recovery_and_says_so() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let mut damaged = pristine;
    damaged[..FILE_HEADER].fill(0);
    let source = MockEvtxSource::new(damaged);
    let limits = Limits {
        records: 10,
        ..Limits::default()
    };
    let r = recover_with_limits(&source, &LiveCoverage::default(), limits);
    assert!(r.tally.records_bound_hit);
    assert_eq!(r.records.len(), 10);
    let status = recovery_status_artifact(Uuid::new_v4(), Uuid::new_v4(), &r);
    assert_eq!(status.metadata["records_bound_hit"], true);
    assert_eq!(status.metadata["limits"]["max_records"], 10);
}

#[test]
fn chunks_embedded_in_unrelated_bytes_at_sector_offsets_are_carved_and_decoded() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let key = live_answer_key(&pristine);
    // Two real chunks dropped into a buffer of the file's own header bytes
    // repeated (not zero, not a chunk), at 512-byte offsets that are not
    // 64 KiB aligned.
    let filler: Vec<u8> = pristine[..FILE_HEADER]
        .iter()
        .cycle()
        .take(3 * CHUNK)
        .copied()
        .collect();
    let mut buffer = filler.clone();
    let at0 = 0x1600;
    let at1 = at0 + CHUNK + 0x800;
    buffer[at0..at0 + CHUNK].copy_from_slice(&pristine[FILE_HEADER..FILE_HEADER + CHUNK]);
    buffer[at1..at1 + CHUNK]
        .copy_from_slice(&pristine[FILE_HEADER + CHUNK..FILE_HEADER + 2 * CHUNK]);
    let out = run(buffer, "unallocated-fragment.bin");

    let recovered = of_type(&out, "EvtxRecoveredLogEntry");
    let got = by_record_id(&recovered);
    assert_eq!(got.len(), 194);
    for (id, want) in &key {
        assert_eq!(got.get(id), Some(want), "record {id}");
    }
    let offsets: std::collections::BTreeSet<u64> = recovered
        .iter()
        .map(|a| a.metadata["chunk_offset"].as_u64().unwrap())
        .collect();
    assert_eq!(offsets, [at0 as u64, at1 as u64].into_iter().collect());
    let s = &of_type(&out, "EvtxRecoveryStatus")[0].metadata;
    assert_eq!(s["chunks_found"], 2);
    assert_eq!(s["chunks_checksum_valid"], 2);
}

#[test]
fn a_file_with_no_chunk_signature_in_its_head_is_left_alone() {
    let data = vec![0x41u8; 200_000];
    let out = run(data, "notes.txt");
    assert!(out.is_empty());
}

#[test]
fn the_probe_sees_a_chunk_signature_anywhere_in_the_first_64_kib() {
    let mut data = vec![0u8; 100_000];
    assert!(!holds_chunk_signature(&MockEvtxSource::new(data.clone())));
    data[60_000..60_008].copy_from_slice(b"ElfChnk\0");
    assert!(holds_chunk_signature(&MockEvtxSource::new(data.clone())));
    let mut late = vec![0u8; 100_000];
    late[70_000..70_008].copy_from_slice(b"ElfChnk\0");
    assert!(
        !holds_chunk_signature(&MockEvtxSource::new(late)),
        "the probe is bounded to the head; a name ending in .evtx is the other route in"
    );
}

#[test]
fn a_recovered_record_is_a_distinct_type_that_a_live_record_can_never_be_mistaken_for() {
    let record = RecoveredRecord {
        offset: 70_144,
        size: 336,
        chunk_offset: Some(69_632),
        source: RecoverySource::LooseRecord,
        chunk_header: ChunkHeaderState::Synthetic,
        header_checksum: ChecksumState::None,
        data_checksum: ChecksumState::None,
        chunk_truncated: false,
        trailer_valid: true,
        event_record_id: 7,
        timestamp: filetime_to_datetime(131_525_251_500_000_000),
        template_id: Some(0x110b_a5fa),
        substitution_count: Some(18),
        xml: Some(
            "<Event><System><Provider Name=\"Svc\"/><EventID>7036</EventID>\
             <EventRecordID>7</EventRecordID><Computer>PC</Computer>\
             <Channel>System</Channel></System></Event>"
                .to_string(),
        ),
        borrowed_template: None,
        incomplete: Vec::new(),
        own_decode_failure: None,
        also_read_live: false,
        containing_chunk_checksums: None,
        failure: None,
    };
    let (entry, timeline) =
        recovered_record_artifacts(Uuid::new_v4(), Uuid::new_v4(), "m", &record);
    assert_eq!(entry.metadata["type"], "EvtxRecoveredLogEntry");
    assert_eq!(entry.metadata["record_type"], "evtx_recovered_record");
    assert_eq!(entry.metadata["recovery_source"], "loose_record");
    assert_eq!(entry.metadata["recovered"], true);
    assert_eq!(entry.metadata["event_id"], 7036);
    assert_eq!(entry.metadata["event_record_id"], 7);
    assert_eq!(entry.metadata["partial"], false);
    assert_eq!(entry.metadata["rendered_with_borrowed_template"], false);
    assert_eq!(entry.metadata["template_id"], "0x110ba5fa");
    assert!(entry.metadata.get("content_incomplete").is_none());
    let timeline = timeline.expect("a dated record reaches the timeline");
    assert_eq!(timeline.metadata["timestamp_desc"], "EventTime (recovered)");
    let details: serde_json::Value =
        serde_json::from_str(timeline.metadata["full_details"].as_str().unwrap()).unwrap();
    assert_eq!(details["recovered"], true);
    assert_eq!(details["recovery_source"], "loose_record");

    // The live shape has no such field, by construction rather than by habit.
    let live = log_entry_metadata(
        &EvtxParser::parse_event_xml(record.xml.as_deref().unwrap()).unwrap(),
        "d",
        "Information",
        record.xml.as_deref().unwrap(),
    );
    assert!(live.get("recovery_source").is_none());
    assert!(live.get("recovered").is_none());
    assert_eq!(live["type"], "EvtxLogEntry");
}

#[test]
fn a_header_only_record_carries_its_facts_and_says_why_there_is_no_content() {
    let record = RecoveredRecord {
        offset: 1000,
        size: 400,
        chunk_offset: None,
        source: RecoverySource::LooseRecord,
        chunk_header: ChunkHeaderState::Synthetic,
        header_checksum: ChecksumState::None,
        data_checksum: ChecksumState::None,
        chunk_truncated: false,
        trailer_valid: true,
        event_record_id: 9,
        timestamp: None,
        template_id: Some(0x1234),
        substitution_count: Some(3),
        xml: None,
        borrowed_template: None,
        incomplete: Vec::new(),
        own_decode_failure: None,
        also_read_live: false,
        containing_chunk_checksums: None,
        failure: Some("no chunk window could be inferred".to_string()),
    };
    let (entry, timeline) =
        recovered_record_artifacts(Uuid::new_v4(), Uuid::new_v4(), "m", &record);
    assert_eq!(entry.metadata["partial"], true);
    assert_eq!(entry.metadata["content_incomplete"], true);
    assert_eq!(
        entry.metadata["content_incomplete_reason"],
        "unresolved_structure"
    );
    assert!(entry.metadata["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("no chunk window"));
    assert!(entry.metadata["full_event_xml"].is_null());
    assert!(entry.metadata["timestamp_utc"].is_null());
    assert!(entry.metadata["timestamp_unreadable_reason"].is_string());
    assert!(timeline.is_none(), "no plausible time, no timeline event");
}

#[test]
fn the_sentinel_splitter_tells_text_attribute_and_element_substitutions_apart() {
    let rendered = "<Event><System><Provider Name=\"\u{E000}3\u{E001}\" Guid=\"{x}\"/>\
                    <EventID>\u{E000}0\u{E001}</EventID></System>\u{E000}12\u{E001}</Event>";
    let segments = split_sentinels(rendered);
    assert_eq!(
        segments,
        vec![
            Segment::Text("<Event><System><Provider".to_string()),
            Segment::AttrSub {
                name: "Name".to_string(),
                index: 3
            },
            Segment::Text(" Guid=\"{x}\"/><EventID>".to_string()),
            Segment::Sub(0),
            Segment::Text("</EventID></System>".to_string()),
            Segment::Sub(12),
            Segment::Text("</Event>".to_string()),
        ]
    );
    assert_eq!(max_substitution_index(&segments), Some(12));
}

#[test]
fn a_filetime_outside_any_plausible_event_range_is_refused_not_rendered() {
    assert!(filetime_to_datetime(0).is_none());
    assert!(filetime_to_datetime(u64::MAX).is_none());
    // 2017-10-15T07:12:30Z in FILETIME.
    let t = filetime_to_datetime(131_525_251_500_000_000).unwrap();
    assert_eq!(t.to_rfc3339(), "2017-10-15T07:12:30+00:00");
}

#[test]
fn junk_named_as_an_event_log_is_scanned_and_reported_as_holding_no_chunks() {
    // Deterministic noise, so the run is repeatable.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let data: Vec<u8> = (0..300_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    let out = run(data, "junk.evtx");
    assert!(of_type(&out, "EvtxRecoveredLogEntry").is_empty());
    let status = of_type(&out, "EvtxRecoveryStatus");
    assert_eq!(
        status.len(),
        1,
        "an input read only by recovery always says what it found"
    );
    let s = &status[0].metadata;
    assert_eq!(s["chunks_found"], 0);
    assert_eq!(s["bytes_scanned"], 300_000);
    assert_eq!(s["inventory_incomplete"], false);
}

#[test]
fn a_recovery_status_with_nothing_lost_carries_no_incompleteness_pair() {
    let r = Recovery {
        records: Vec::new(),
        tally: RecoveryTally {
            bytes_declared: 10,
            bytes_scanned: 10,
            ..RecoveryTally::default()
        },
        limits: Limits::default(),
        chunks: Vec::new(),
    };
    let status = recovery_status_artifact(Uuid::new_v4(), Uuid::new_v4(), &r);
    assert_eq!(status.metadata["content_incomplete"], false);
    assert!(status.metadata["content_incomplete_reason"].is_null());
    assert_eq!(status.metadata["counts_are_floor"], false);
    assert_eq!(status.metadata["limits"]["max_scan_bytes"], MAX_SCAN_BYTES);
}

/// A source that declares more bytes than it will ever hand back: a sparse
/// or short-mapped image, a stream cut off under the reader.
#[derive(Debug)]
struct OverdeclaringSource {
    inner: MockEvtxSource,
    declared: u64,
}

impl DataSource for OverdeclaringSource {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read_at(offset, buffer)
    }

    fn size(&self) -> u64 {
        self.declared
    }
}

/// Deterministic noise with no chunk or record signature in it.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[test]
fn a_source_that_declares_more_than_it_returns_is_a_short_read_not_a_complete_scan() {
    let have = 200_000u64;
    let declared = have + 1_000_000;
    let source = OverdeclaringSource {
        inner: MockEvtxSource::new(noise(have as usize)),
        declared,
    };
    let r = recover(&source, &LiveCoverage::default());
    assert_eq!(r.tally.bytes_declared, declared);
    assert_eq!(r.tally.bytes_scanned, have);
    assert!(r.tally.short_read, "what was not read was not scanned");
    assert!(
        !r.tally.scan_bound_hit,
        "no bound was hit; the source ran out"
    );

    let status = recovery_status_artifact(Uuid::new_v4(), Uuid::new_v4(), &r);
    let s = &status.metadata;
    assert_eq!(s["bytes_declared"], declared);
    assert_eq!(s["bytes_scanned"], have);
    assert_eq!(s["short_read"], true);
    assert_eq!(s["inventory_incomplete"], true);
    assert_eq!(s["counts_are_floor"], true);
    assert_eq!(s["content_incomplete"], true);
    assert!(s["content_incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("short_read"));
    let message = s["message"].as_str().unwrap();
    assert!(
        message.contains("1200000") && message.contains("200000") && message.contains("1000000"),
        "the message names declared, scanned and unscanned bytes: {message}"
    );
}

#[test]
fn a_short_read_reaches_the_examiner_even_when_the_intact_parser_read_the_file_whole() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let have = pristine.len() as u64;
    let source: Arc<dyn DataSource> = Arc::new(OverdeclaringSource {
        inner: MockEvtxSource::new(pristine),
        declared: have + 4096,
    });
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        json!({ "name": "System2.evtx" }),
    );
    let out = EvtxParser.process(&artifact).expect("process returns Ok");
    let status = of_type(&out, "EvtxRecoveryStatus");
    assert_eq!(status.len(), 1);
    let s = &status[0].metadata;
    assert_eq!(s["short_read"], true);
    assert_eq!(s["bytes_declared"], have + 4096);
    assert_eq!(s["bytes_scanned"], have);
    assert_eq!(s["counts_are_floor"], true);
}

#[test]
fn a_source_read_whole_is_not_a_short_read() {
    let source = MockEvtxSource::new(noise(100_000));
    let r = recover(&source, &LiveCoverage::default());
    assert_eq!(r.tally.bytes_declared, 100_000);
    assert_eq!(r.tally.bytes_scanned, 100_000);
    assert!(!r.tally.short_read);
    let status = recovery_status_artifact(Uuid::new_v4(), Uuid::new_v4(), &r);
    assert_eq!(status.metadata["short_read"], false);
    assert_eq!(status.metadata["counts_are_floor"], false);
}

#[test]
fn the_truncated_chunk_is_listed_by_offset_with_its_checksum_states_and_record_count() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let out = run(pristine, "System2.evtx");
    let s = &of_type(&out, "EvtxRecoveryStatus")[0].metadata;
    let listing = &s["chunk_listing"];
    assert_eq!(listing["bound"], MAX_LISTED_CHUNKS);
    assert_eq!(listing["bound_hit"], false);
    assert_eq!(listing["omitted"], 0);
    // The two whole chunks verified and were read live in full: nothing to
    // say beyond the count. The third is cut short and is the one listed.
    assert_eq!(listing["listed"], 1);
    let chunks = listing["chunks"].as_array().expect("a per-chunk listing");
    assert_eq!(chunks.len(), 1);
    let c = &chunks[0];
    assert_eq!(c["offset"], (FILE_HEADER + 2 * CHUNK) as u64);
    assert_eq!(c["header_checksum"], "valid");
    assert_eq!(c["data_checksum"], "unverifiable_truncated");
    assert_eq!(c["truncated"], true);
    assert_eq!(c["read_live_whole"], false);
    assert_eq!(c["records_recovered"], 90);
    assert_eq!(c["chunk_header"], "present");
}

#[test]
fn every_failed_checksum_chunk_is_listed_by_offset_until_the_bound_and_the_bound_is_named() {
    // Three chunk signatures over zeroed headers, at sector offsets in noise:
    // each has a checksum that cannot verify and is a chunk of note.
    let mut data = noise(4 * CHUNK);
    let offsets = [512usize, 3 * 4096 + CHUNK, 2 * CHUNK + 8192];
    for &at in &offsets {
        data[at..at + CHUNK_HEADER_SIZE].fill(0);
        data[at..at + 8].copy_from_slice(b"ElfChnk\0");
    }
    let source = MockEvtxSource::new(data);

    let r = recover(&source, &LiveCoverage::default());
    assert_eq!(r.tally.chunks_found, 3);
    assert_eq!(r.tally.chunks_checksum_failed, 3);
    assert_eq!(r.chunks.len(), 3);
    let listed: Vec<u64> = r.chunks.iter().map(|c| c.offset).collect();
    let mut expected: Vec<u64> = offsets.iter().map(|&o| o as u64).collect();
    expected.sort_unstable();
    assert_eq!(listed, expected, "listed in offset order");
    for c in &r.chunks {
        assert_eq!(c.header_checksum, ChecksumState::Failed);
        assert_eq!(c.data_checksum, ChecksumState::Failed);
        assert_eq!(c.records_recovered, 0);
    }
    let status = recovery_status_artifact(Uuid::new_v4(), Uuid::new_v4(), &r);
    let listing = &status.metadata["chunk_listing"];
    assert_eq!(listing["listed"], 3);
    assert_eq!(listing["omitted"], 0);
    assert_eq!(listing["bound_hit"], false);
    assert_eq!(listing["chunks"][1]["header_checksum"], "failed");
    assert_eq!(listing["chunks"][1]["offset"], expected[1]);

    // Narrow the bound below the count: the listing stops, says so, and the
    // counts above it are untouched.
    let limits = Limits {
        listed_chunks: 2,
        ..Limits::default()
    };
    let r = recover_with_limits(&source, &LiveCoverage::default(), limits);
    assert_eq!(r.tally.chunks_checksum_failed, 3);
    assert_eq!(r.chunks.len(), 2);
    assert!(r.tally.chunk_listing_bound_hit);
    assert_eq!(r.tally.chunks_not_listed, 1);
    let status = recovery_status_artifact(Uuid::new_v4(), Uuid::new_v4(), &r);
    let listing = &status.metadata["chunk_listing"];
    assert_eq!(listing["bound"], 2);
    assert_eq!(listing["bound_hit"], true);
    assert_eq!(listing["listed"], 2);
    assert_eq!(listing["omitted"], 1);
    assert_eq!(listing["chunks"].as_array().unwrap().len(), 2);
    let message = status.metadata["message"].as_str().unwrap();
    assert!(
        message.contains("bound of 2 chunk") && message.contains("1 chunk(s) of note"),
        "the message names the listing bound and how many chunks fell past it: {message}"
    );
    // The listing is a bound on the listing, not on the recovery: the
    // inventory of records is not what fell short.
    assert_eq!(status.metadata["counts_are_floor"], false);
}

/// `HUNT-162`: the intact walk stopped at `(size − 4096) / 65536` whole chunks
/// and never said so. plaso's `System2.evtx` ends 64,832 bytes into its third
/// chunk; the walk read the two whole chunks, emitted their 194 events and no
/// `EvtxParseStatus` at all, so the intact parse read as complete while 89
/// records sat in bytes it never looked at. The walk's own status record now
/// counts the chunk, names its offset and how much of it survives, and points
/// at the recovery pass that reads it — the two records agree about the file.
#[test]
fn the_intact_walk_counts_the_chunk_cut_short_at_end_of_file() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let out = run(pristine, "System2.evtx");
    assert_eq!(of_type(&out, "EvtxLogEntry").len(), 194);
    let status = of_type(&out, "EvtxParseStatus");
    assert_eq!(
        status.len(),
        1,
        "the intact walk must say it did not read the file's last chunk"
    );
    let s = &status[0].metadata;
    assert_eq!(s["chunks_truncated_at_eof"], 1);
    assert_eq!(
        s["truncated_chunk_offset"],
        (FILE_HEADER + 2 * CHUNK) as u64
    );
    assert_eq!(s["truncated_chunk_bytes_present"], 64_832);
    assert_eq!(s["chunks_read"], 2);
    assert_eq!(s["records_failed"], 0);
    assert_eq!(s["inventory_incomplete"], true);
    assert_eq!(s["counts_are_floor"], false);
    assert_eq!(
        s["content_incomplete_reason"],
        "chunk_truncated_at_end_of_file"
    );
    let message = s["message"].as_str().unwrap();
    assert!(
        message.contains("135168") && message.contains("EvtxRecoveryStatus"),
        "the message names the chunk and where its records went: {message}"
    );
    // The recovery pass lists the same chunk: the two records never disagree.
    let r = &of_type(&out, "EvtxRecoveryStatus")[0].metadata;
    assert_eq!(r["chunks_truncated"], 1);
}

/// The same fault on a second real log, cut where an examiner's copy is cut:
/// omerbenamram's `system.evtx` truncated 20,000 bytes into chunk 14, whose
/// records run to 30,264. Fourteen whole chunks read live; the fifteenth is
/// counted by the walk, not dropped.
#[test]
fn a_real_log_truncated_mid_chunk_has_its_tail_chunk_counted_by_the_intact_walk() {
    let Some(pristine) = corpus_bytes("system.evtx") else {
        return;
    };
    let cut_at = FILE_HEADER + 14 * CHUNK;
    let truncated = pristine[..cut_at + 20_000].to_vec();
    let out = run(truncated, "system.evtx");
    let s = &of_type(&out, "EvtxParseStatus")
        .first()
        .expect("a truncated tail chunk is disclosed by the intact walk")
        .metadata;
    assert_eq!(s["chunks_truncated_at_eof"], 1);
    assert_eq!(s["truncated_chunk_offset"], cut_at as u64);
    assert_eq!(s["truncated_chunk_bytes_present"], 20_000);
    assert_eq!(s["chunks_read"], 14);
    // Its records are recovered from the bytes that survive.
    let from_tail = of_type(&out, "EvtxRecoveredLogEntry")
        .into_iter()
        .filter(|a| a.metadata["chunk_offset"] == cut_at as u64)
        .count();
    assert!(
        from_tail > 0,
        "the cut chunk's surviving records are recovered"
    );
}

/// A file that ends exactly on a chunk boundary has no tail to disclose, and
/// the pristine `system.evtx` (seventeen whole chunk slots) keeps its silence.
#[test]
fn a_log_that_ends_on_a_chunk_boundary_reports_no_truncated_chunk() {
    let Some(pristine) = corpus_bytes("system.evtx") else {
        return;
    };
    let out = run(pristine, "system.evtx");
    assert!(
        of_type(&out, "EvtxParseStatus").is_empty(),
        "a whole file raises no parse-status record"
    );
}

/// `HUNT-164` on the real bytes: plaso's `System2.evtx` third chunk, as cut,
/// handed to the vendored crate's own checksum check. It panicked with an
/// index out of bounds (`free_space_offset` 65,088 of 64,832 bytes).
#[test]
fn the_vendored_data_checksum_does_not_panic_on_a_real_truncated_chunk() {
    let Some(pristine) = corpus_bytes("System2.evtx") else {
        return;
    };
    let tail = pristine[FILE_HEADER + 2 * CHUNK..].to_vec();
    let chunk = evtx::EvtxChunkData::new(tail, false).expect("the header is whole");
    let verdict = std::panic::catch_unwind(|| chunk.validate_data_checksum());
    assert_eq!(verdict.ok(), Some(false));
}

/// `HUNT-165`: a slack record was published with `chunk_header: synthetic`
/// beside the LIVE chunk's checksum states. The data CRC covers bytes
/// 512..`free_space_offset` — not the slack the record was read from — so
/// `chunk_data_checksum: valid` claimed a verification no checksum made. A
/// slack record now carries `not_applicable` for both, says why, and keeps
/// the containing chunk's own states under names that say whose they are.
#[test]
fn a_slack_record_does_not_claim_the_live_chunks_checksums_cover_it() {
    let Some(pristine) = corpus_bytes("system.evtx") else {
        return;
    };
    let out = run(pristine, "system.evtx");
    let slack: Vec<_> = of_type(&out, "EvtxRecoveredLogEntry")
        .into_iter()
        .filter(|a| a.metadata["recovery_source"] == "chunk_slack")
        .collect();
    assert_eq!(slack.len(), 79);
    for a in &slack {
        let m = &a.metadata;
        assert_eq!(m["chunk_header"], "synthetic");
        assert_eq!(
            m["chunk_header_checksum"], "not_applicable",
            "no checksum covers a slack record's bytes: {m}"
        );
        assert_eq!(m["chunk_data_checksum"], "not_applicable");
        assert_eq!(m["containing_chunk_header_checksum"], "valid");
        assert_eq!(m["containing_chunk_data_checksum"], "valid");
        let why = m["chunk_checksum_note"].as_str().unwrap_or("");
        assert!(
            why.contains("free-space offset") && why.contains("slack"),
            "the record says why the checksums do not cover it: {why}"
        );
    }
    // A carved-chunk record keeps its own chunk's states and no such note.
    let carved = of_type(&out, "EvtxRecoveredLogEntry")
        .into_iter()
        .find(|a| a.metadata["recovery_source"] == "carved_chunk");
    if let Some(a) = carved {
        assert_ne!(a.metadata["chunk_data_checksum"], "not_applicable");
        assert!(a.metadata.get("chunk_checksum_note").is_none());
    }
}
