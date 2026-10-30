//! From scanned repository records to `AsepEntry` records.
//!
//! One entry is emitted per instance record the scan matched — decoded or
//! not. A binding entry carries the resolution of both ends: the filter it
//! names and the consumer it names, looked up among the records of the same
//! scan by the key each object path carries. An end that resolves brings its
//! decoded properties along; an end that does not is stated as not found,
//! which is an incomplete answer and is marked as one.

use crate::record::{AsepEntry, EvidenceState, InstalledTime, LocationKind, ReadStatus};
use crate::wmi::{
    consumer_action, parse_object_path, ConsumerAction, DecodeStatus, PageState, PropValue,
    RecordProvenance, ScanOutcome, WmiRecord,
};
use crate::wmi_index::IndexRead;
use seance_core::io::IncompleteReason;
use seance_core::time::filetime_to_rfc3339;
use serde_json::{json, Map, Value};

/// The statement every WMI entry carries about how it was found.
pub const SCAN_BASIS: &str =
    "Found by a record-level scan of OBJECTS.DATA: the file's pages were read, each page's \
     descriptor table was parsed, and records beginning with the class-name hash of a \
     subscription class were decoded against the class definitions in the same file. The \
     index (INDEX.BTR) and the page mapping (MAPPING*.MAP) were not read, so whether this \
     record was the one the repository currently mapped -- rather than a superseded copy in \
     a page no longer mapped -- was not established.";

const ENABLED_BASIS: &str =
    "WMI subscriptions carry no enabled flag. A binding whose filter and consumer both exist \
     is in force whenever the WMI service runs. Whether this record was current at \
     acquisition was not established, because the page mapping was not read.";

/// Where a record read through the page mapping stands (HUNT-195). The
/// page's place in the mapping says only whether the *page* is current; a
/// record no descriptor table lists is residue even in a current page.
#[derive(Clone, Copy)]
enum Standing {
    /// Listed by the descriptor table of a page the mapping names, and named
    /// by the repository's index, walked from its root (HUNT-195).
    Indexed { logical: usize },
    /// Listed by the descriptor table of a page the mapping names, but named
    /// by no key of the index tree: deleted or unlinked.
    ListedNotIndexed { logical: usize },
    /// Listed by the descriptor table of a page the mapping names; the index
    /// was not read, so nothing more is known.
    Listed { logical: usize },
    /// In a page the mapping names, but listed by no descriptor table: slack
    /// or residue inside a current page.
    Residue { logical: usize },
    /// In a page the mapping maps to no logical page.
    Superseded,
    /// In the trailing part-page no entry of the mapping covers.
    BeyondMapping,
    /// Anything else (not expected when a mapping was read): nothing is claimed.
    Unplaced,
}

fn standing(rec: &WmiRecord) -> Standing {
    match (rec.page_state, &rec.provenance) {
        (PageState::Unmapped, _) => Standing::Superseded,
        (PageState::BeyondMapping, _) => Standing::BeyondMapping,
        (PageState::Mapped { logical }, RecordProvenance::AllocatedPageRecord) => {
            match rec.indexed {
                Some(true) => Standing::Indexed { logical },
                Some(false) => Standing::ListedNotIndexed { logical },
                None => Standing::Listed { logical },
            }
        }
        (PageState::Mapped { logical }, RecordProvenance::UnreferencedBytes) => {
            Standing::Residue { logical }
        }
        (PageState::Continuation { .. } | PageState::MappingNotRead, _) => Standing::Unplaced,
    }
}

/// How a record read through the page mapping was found, by where it stands
/// in that mapping and, where the index was read, in the index (HUNT-195).
/// `file` and `sequence` name the mapping used.
fn mapped_scan_basis(file: &str, sequence: u32, standing: Standing, index: &IndexRead) -> String {
    let how = format!(
        "Found by a record-level scan of OBJECTS.DATA read through the repository's page \
         mapping ({file}, sequence number {sequence}): the pages were walked in logical order, \
         each page's descriptor table was parsed, a record running past its page was read on \
         into the next logical page the mapping names, and records beginning with the \
         class-name hash of a subscription class were decoded against the class definitions \
         in the same file."
    );
    let unread = match index {
        IndexRead::Unread(why) => format!(" The index (INDEX.BTR) was not read: {why}."),
        IndexRead::Read(_) => String::new(),
    };
    let currency = match standing {
        Standing::Indexed { logical } => format!(
            " This record's page is logical page {logical} of the mapping, and the repository's \
             index (INDEX.BTR), walked from its root, names this record by that page, its \
             descriptor id and its size, so it is a record the repository resolves."
        ),
        Standing::ListedNotIndexed { logical } => format!(
            " This record's page is logical page {logical} of the mapping and its descriptor \
             table lists the record, but the repository's index (INDEX.BTR), walked from its \
             root, names no record by that page, id and size: the record is deleted or \
             unlinked, not one the repository resolves. It may show what was once configured."
        ),
        Standing::Listed { logical } => format!(
            " This record's page is logical page {logical} of the mapping, so it is in the \
             repository's current page set. The index (INDEX.BTR) was not read, so that the \
             record is current rests on its page's own descriptor table listing it, not on \
             the index naming it.{}",
            match index {
                IndexRead::Unread(why) => format!(" Why: {why}."),
                IndexRead::Read(_) => String::new(),
            }
        ),
        Standing::Residue { logical } => format!(
            " This record's page is logical page {logical} of the mapping, but no descriptor \
             table lists the record: its bytes lie in slack or freed space inside that page, \
             so it is residue, not a record the repository currently holds. The page being \
             mapped says only that the page is current.{unread}"
        ),
        Standing::Superseded => format!(
            " This record's page is mapped to no logical page: it is a free page, so the \
             record is a superseded or free-page copy, not one the repository currently \
             holds.{unread}"
        ),
        Standing::BeyondMapping => format!(
            " This record lies in the trailing part-page past the last whole page of the \
             file; the mapping accounts for whole pages only, so no entry of the mapping \
             covers these bytes and no descriptor table lists the record. It is not \
             established to be a record the repository currently holds.{unread}"
        ),
        Standing::Unplaced => {
            if unread.is_empty() {
                String::new()
            } else {
                unread
            }
        }
    };
    how + &currency
}

fn mapped_enabled_basis(standing: Standing) -> &'static str {
    match standing {
        Standing::Indexed { .. } => {
            "WMI subscriptions carry no enabled flag. A binding whose filter and consumer both \
             exist is in force whenever the WMI service runs. The record's page is in the \
             repository's current page mapping and the index (INDEX.BTR), walked from its \
             root, names the record."
        }
        Standing::ListedNotIndexed { .. } => {
            "WMI subscriptions carry no enabled flag. A descriptor table lists this record but \
             the index (INDEX.BTR), walked from its root, does not name it: it is deleted or \
             unlinked, so it is not in force as found; it may show what was once configured."
        }
        Standing::Listed { .. } => {
            "WMI subscriptions carry no enabled flag. A binding whose filter and consumer both \
             exist is in force whenever the WMI service runs. The record's page is in the \
             repository's current page mapping and its descriptor table lists the record; \
             the index (INDEX.BTR) was not read."
        }
        Standing::Superseded => {
            "WMI subscriptions carry no enabled flag. This record is a superseded or \
             free-page copy -- its page is mapped to no logical page -- so it is not in force \
             as found; it may show what was once configured."
        }
        Standing::Residue { .. } => {
            "WMI subscriptions carry no enabled flag. No descriptor table lists this record: \
             it is residue inside a mapped page, so it is not in force as found; it may show \
             what was once configured."
        }
        Standing::BeyondMapping => {
            "WMI subscriptions carry no enabled flag. This record lies past every page the \
             mapping covers and no descriptor table lists it, so it is not in force as found; \
             it may show what was once configured."
        }
        Standing::Unplaced => {
            "WMI subscriptions carry no enabled flag. Whether this record was current at \
             acquisition was not established."
        }
    }
}

fn repository_liveness(standing: Standing) -> &'static str {
    match standing {
        Standing::Indexed { .. } => "indexed",
        Standing::ListedNotIndexed { .. } => "listed_not_indexed",
        Standing::Listed { .. } => "in_mapped_page_index_not_read",
        Standing::Residue { .. } => "unreferenced_in_mapped_page",
        Standing::Superseded => "superseded_page",
        Standing::BeyondMapping => "beyond_mapping",
        Standing::Unplaced => "not_established",
    }
}

/// Order in which copies of the same named object are preferred as the end a
/// binding resolves to, best first: a record the current mapping's descriptor
/// tables list (and the index names, where it was read), then one the index
/// leaves unnamed, then residue in a mapped page, then bytes past the mapping,
/// then a copy in a page no logical page maps to. Without a mapping only the
/// descriptor listing is known, so a listed record comes before residue.
fn currency_rank(rec: &WmiRecord, mapping_read: bool) -> u8 {
    if !mapping_read {
        return match rec.provenance {
            RecordProvenance::AllocatedPageRecord => 0,
            RecordProvenance::UnreferencedBytes => 1,
        };
    }
    match standing(rec) {
        Standing::Indexed { .. } | Standing::Listed { .. } => 0,
        Standing::ListedNotIndexed { .. } => 1,
        Standing::Residue { .. } => 2,
        Standing::BeyondMapping => 3,
        Standing::Superseded => 4,
        Standing::Unplaced => 5,
    }
}

/// Whether the mapping, and the index where it was read, establish the record
/// as one the repository currently holds. Only asked when a mapping was read.
fn is_current(rec: &WmiRecord) -> bool {
    matches!(
        standing(rec),
        Standing::Indexed { .. } | Standing::Listed { .. }
    )
}

/// How a record that is not current stands, in words, for a sentence that
/// says a binding end was found only as such a copy.
fn not_current_phrase(rec: &WmiRecord) -> &'static str {
    match standing(rec) {
        Standing::Superseded => "a superseded copy in a page the mapping maps to no logical page",
        Standing::Residue { .. } => "residue no descriptor table lists, inside a mapped page",
        Standing::BeyondMapping => "bytes past every page the mapping covers",
        Standing::ListedNotIndexed { .. } => {
            "a record a mapped page's descriptor table lists but the index does not name"
        }
        Standing::Indexed { .. } | Standing::Listed { .. } | Standing::Unplaced => {
            "a copy whose currency was not established"
        }
    }
}

/// Sort candidate copies best first (see [`currency_rank`]), then by offset.
fn by_currency(mut recs: Vec<&WmiRecord>, mapping_read: bool) -> Vec<&WmiRecord> {
    recs.sort_by_key(|r| (currency_rank(r, mapping_read), r.offset));
    recs
}

const TIME_BASIS: &str =
    "The record header carries two FILETIME values, both on the record as record_filetime_a and \
     record_filetime_b. The later is reported as the record time, and it is NOT the time the \
     subscription was made: on a Windows 11 repository where instances were planted at known \
     times, each carried a time before it was created, by 76 minutes, 6 minutes and 3 seconds \
     in three waves, behaving as the repository's previous commit, while the other value was \
     the instance's class definition time and matched across every instance of a class. The \
     subscription was therefore made no earlier than the record time, and how much later is \
     not stated (VALIDATION.md WMI-5; one machine, one build).";

/// Turn a scan into entries, one per matched record.
pub fn entries_from_scan(outcome: &ScanOutcome, path: &str) -> Vec<AsepEntry> {
    let records = &outcome.records;
    let mapping = outcome
        .mapping_file
        .as_ref()
        .map(|(file, seq)| (file.as_str(), *seq, &outcome.index));
    records
        .iter()
        .map(|rec| entry_for(rec, records, path, mapping))
        .collect()
}

fn entry_for(
    rec: &WmiRecord,
    all: &[WmiRecord],
    path: &str,
    mapping: Option<(&str, u32, &IndexRead)>,
) -> AsepEntry {
    let class = rec.class_name.as_str();
    let decoded = matches!(rec.decode, DecodeStatus::Decoded { .. });
    let name = rec.text("Name").map(str::to_string);

    let mut entry = AsepEntry::new(
        "wmi_event_subscription",
        format!("{class} record at {:#x}", rec.offset),
        path,
        LocationKind::File,
    );
    entry.scope = "filesystem".to_string();
    entry.evidence_state = match (&rec.provenance, rec.page_state) {
        (RecordProvenance::AllocatedPageRecord, PageState::Unmapped) => EvidenceState::Superseded,
        (RecordProvenance::AllocatedPageRecord, PageState::Mapped { .. })
            if rec.indexed == Some(false) =>
        {
            EvidenceState::Unlinked
        }
        (RecordProvenance::AllocatedPageRecord, _) => EvidenceState::AllocatedRecord,
        (RecordProvenance::UnreferencedBytes, _) => EvidenceState::Recovered,
    };
    entry.enabled = None;
    entry.enabled_basis = match mapping {
        Some(_) => mapped_enabled_basis(standing(rec)).to_string(),
        None => ENABLED_BASIS.to_string(),
    };
    attach_record_fields(&mut entry, rec, mapping);

    match &rec.decode {
        DecodeStatus::Undecodable(reason) => {
            entry.read_status = ReadStatus::Unread(reason.clone());
            entry.incomplete_reason = Some(reason.clone());
            entry.incomplete_code = Some(IncompleteReason::UnresolvedStructure);
            entry.runs_when = format!(
                "A {class} instance record exists at offset {:#x}; it was not decoded, so what \
                 it defines could not be stated. The strings it holds are listed on the record.",
                rec.offset
            );
            entry.installed_time_unavailable_reason =
                Some("The record was not decoded, so its timestamps were not taken as evidence.");
            return entry;
        }
        DecodeStatus::Decoded { .. } => {}
    }

    // The later of the two header FILETIMEs is a record time: a bound on when the
    // subscription was made, never the time itself (`HUNT-195`, `TIME_BASIS`).
    let later = rec.filetime_a.max(rec.filetime_b);
    match filetime_to_rfc3339(later) {
        Some(ts) => {
            entry.record_time = Some(InstalledTime {
                value: ts,
                source: "wmi_record_filetime_later_of_two",
                timezone: None,
            });
            entry.installed_time_unavailable_reason = Some(
                "A WMI record carries no installation time: its header FILETIMEs are the \
                 repository's previous commit and the class definition's time, so the \
                 subscription was made no earlier than the record time and how much later is \
                 not stated.",
            );
            entry.put("record_time_basis", json!(TIME_BASIS));
        }
        None => {
            entry.installed_time_unavailable_reason = Some(
                "Neither FILETIME in the record header is a usable timestamp (zero or out of \
                 range).",
            );
        }
    }

    if class.eq_ignore_ascii_case("__EventFilter") {
        describe_filter(&mut entry, rec, all, name, mapping.is_some());
    } else if class.eq_ignore_ascii_case("__FilterToConsumerBinding") {
        describe_binding(&mut entry, rec, all, mapping.is_some());
    } else {
        describe_consumer(&mut entry, rec, all, name, mapping.is_some());
    }
    if decoded && rec.spans_pages && !rec.reassembled {
        entry.incomplete_reason = Some(
            "The descriptor's size runs past the page; only the part on this page was read."
                .to_string(),
        );
        entry.incomplete_code = Some(IncompleteReason::UnresolvedStructure);
    }
    entry
}

/// Fields every WMI entry carries, decoded or not.
fn attach_record_fields(
    entry: &mut AsepEntry,
    rec: &WmiRecord,
    mapping: Option<(&str, u32, &IndexRead)>,
) {
    entry.put("wmi_record_class", json!(rec.class_name));
    entry.put("record_offset", json!(rec.offset));
    entry.put("record_size", json!(rec.size));
    entry.put("record_page", json!(rec.page));
    entry.put("record_id", json!(rec.record_id));
    entry.put("record_provenance", json!(rec.provenance.as_str()));
    entry.put("record_checksum", json!(rec.checksum.as_str()));
    if let crate::wmi::ChecksumStatus::Mismatch { stored, computed } = rec.checksum {
        entry.put("record_checksum_stored", json!(format!("{stored:#010x}")));
        entry.put(
            "record_checksum_computed",
            json!(format!("{computed:#010x}")),
        );
    }
    entry.put("record_spans_pages", json!(rec.spans_pages));
    entry.put("class_hash_form", json!(rec.hash_form.as_str()));
    entry.put("record_filetime_a_raw", json!(rec.filetime_a));
    entry.put("record_filetime_b_raw", json!(rec.filetime_b));
    entry.put(
        "record_filetime_a",
        json!(filetime_to_rfc3339(rec.filetime_a)),
    );
    entry.put(
        "record_filetime_b",
        json!(filetime_to_rfc3339(rec.filetime_b)),
    );
    entry.put("data_strings", json!(rec.data_strings));
    entry.put("data_strings_truncated", json!(rec.data_strings_truncated));
    match mapping {
        Some((file, seq, index)) => {
            entry.put(
                "scan_basis",
                json!(mapped_scan_basis(file, seq, standing(rec), index)),
            );
            entry.put(
                "repository_liveness",
                json!(repository_liveness(standing(rec))),
            );
            entry.put("mapping_read", json!(true));
            entry.put("mapping_file", json!(file));
            entry.put("mapping_sequence", json!(seq));
        }
        None => {
            entry.put("scan_basis", json!(SCAN_BASIS));
            entry.put("repository_liveness", json!("not_established"));
            entry.put("mapping_read", json!(false));
        }
    }
    entry.put(
        "index_walked",
        json!(matches!(mapping, Some((_, _, IndexRead::Read(_))))),
    );
    entry.put("record_indexed", json!(rec.indexed));
    entry.put("record_page_state", json!(rec.page_state.as_str()));
    if let PageState::Mapped { logical } = rec.page_state {
        entry.put("record_logical_page", json!(logical));
    }
    entry.put("record_reassembled", json!(rec.reassembled));
    if let DecodeStatus::Decoded { layout_offset } = rec.decode {
        entry.put("class_definition_offset", json!(layout_offset));
    }
    if !rec.notes.is_empty() {
        entry.put("decode_notes", json!(rec.notes));
    }
    if !rec.properties.is_empty() {
        let mut props = Map::new();
        for p in &rec.properties {
            props.insert(
                p.name.clone(),
                json!({
                    "value": prop_json(&p.value),
                    "state": p.state.as_str(),
                    "cim_type": p.cim_type,
                }),
            );
        }
        entry.put("properties", Value::Object(props));
    }
    if let Some(sid) = &rec.creator_sid {
        entry.put("creator_sid", json!(sid));
    }
}

fn prop_json(v: &PropValue) -> Value {
    match v {
        PropValue::Str(s) => json!(s),
        PropValue::Bool(b) => json!(b),
        PropValue::Signed(i) => json!(i),
        PropValue::Unsigned(u) => json!(u),
        PropValue::Real(r) => json!(r),
        PropValue::Bytes(b) => json!(b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
        PropValue::StrArray(a) => json!(a),
        PropValue::Null => Value::Null,
        PropValue::Undecoded(reason) => json!({ "undecoded": reason }),
    }
}

fn filters_named<'a>(all: &'a [WmiRecord], name: &str) -> Vec<&'a WmiRecord> {
    all.iter()
        .filter(|r| {
            r.class_name.eq_ignore_ascii_case("__EventFilter")
                && r.text("Name").is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
        .collect()
}

fn consumers_named<'a>(all: &'a [WmiRecord], class: &str, name: &str) -> Vec<&'a WmiRecord> {
    all.iter()
        .filter(|r| {
            r.class_name.eq_ignore_ascii_case(class)
                && r.text("Name").is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
        .collect()
}

fn bindings(all: &[WmiRecord]) -> impl Iterator<Item = &WmiRecord> {
    all.iter().filter(|r| {
        r.class_name
            .eq_ignore_ascii_case("__FilterToConsumerBinding")
    })
}

/// The `Name` a binding's Filter or Consumer path carries.
fn ref_name(path: Option<&str>) -> Option<(String, String)> {
    let r = parse_object_path(path?)?;
    Some((r.class, r.value?))
}

/// Bindings that name an object, split by currency. With a mapping read, a
/// binding whose record the mapping does not establish as current is kept
/// apart, so a superseded or residue binding is never counted as one in force.
/// Without a mapping no currency is claimed and every binding is in `current`.
struct BoundBy {
    current: Vec<String>,
    not_current: Vec<String>,
}

fn bound_by<'a>(
    all: &'a [WmiRecord],
    mapping_read: bool,
    names_this: impl Fn(&WmiRecord) -> bool,
    other_end: impl Fn(&'a WmiRecord) -> Option<String>,
) -> BoundBy {
    let mut out = BoundBy {
        current: Vec::new(),
        not_current: Vec::new(),
    };
    for b in bindings(all).filter(|b| names_this(b)) {
        let Some(label) = other_end(b) else { continue };
        if !mapping_read || is_current(b) {
            out.current.push(label);
        } else {
            out.not_current.push(label);
        }
    }
    out
}

/// The sentence naming bindings the mapping does not establish as current.
fn not_current_sentence(labels: &[String], what: &str) -> String {
    if labels.is_empty() {
        return String::new();
    }
    format!(
        " Also named by {} __FilterToConsumerBinding record(s) that are not current as \
         found -- the page mapping does not establish them as current (superseded copies or \
         residue) -- which bind it to {what} {}; those are not in force as found.",
        labels.len(),
        labels.join(", ")
    )
}

fn describe_filter(
    entry: &mut AsepEntry,
    rec: &WmiRecord,
    all: &[WmiRecord],
    name: Option<String>,
    mapping_read: bool,
) {
    let display = name
        .clone()
        .unwrap_or_else(|| "(unnamed __EventFilter)".to_string());
    entry.entry_name = display.clone();
    let query = rec.text("Query").unwrap_or("(no Query stored)");
    let language = rec.text("QueryLanguage").unwrap_or("unstated language");
    let ns = rec
        .text("EventNamespace")
        .unwrap_or("(no EventNamespace stored)");
    let bound = match name.as_deref() {
        Some(n) => bound_by(
            all,
            mapping_read,
            |b| ref_name(b.text("Filter")).is_some_and(|(_, v)| v.eq_ignore_ascii_case(n)),
            |b| ref_name(b.text("Consumer")).map(|(c, v)| format!("{c} '{v}'")),
        ),
        None => BoundBy {
            current: Vec::new(),
            not_current: Vec::new(),
        },
    };
    entry.put("filter_query", json!(query));
    entry.put("filter_query_language", json!(language));
    entry.put("filter_namespace", json!(ns));
    entry.put("filter_bound_consumers", json!(bound.current));
    if mapping_read {
        entry.put(
            "filter_bound_consumers_not_current",
            json!(bound.not_current),
        );
    }
    let defines = format!("Defines the {language} event query {query:?} in namespace {ns}.");
    let also = not_current_sentence(&bound.not_current, "consumer(s)");
    entry.runs_when = if bound.current.is_empty() {
        let none = if mapping_read {
            "No __FilterToConsumerBinding the page mapping establishes as current names this \
             filter, so on its own it triggers nothing."
        } else {
            "No __FilterToConsumerBinding found by this scan names this filter, so on its own \
             it triggers nothing."
        };
        format!("{defines} {none}{also}")
    } else {
        format!("{defines} Bound to {}.{also}", bound.current.join(", "))
    };
}

fn describe_consumer(
    entry: &mut AsepEntry,
    rec: &WmiRecord,
    all: &[WmiRecord],
    name: Option<String>,
    mapping_read: bool,
) {
    let display = name
        .clone()
        .unwrap_or_else(|| format!("(unnamed {})", rec.class_name));
    entry.entry_name = display;
    let action = consumer_action(rec);
    apply_action(entry, &action);
    let bound = match name.as_deref() {
        Some(n) => bound_by(
            all,
            mapping_read,
            |b| {
                ref_name(b.text("Consumer")).is_some_and(|(c, v)| {
                    c.eq_ignore_ascii_case(&rec.class_name) && v.eq_ignore_ascii_case(n)
                })
            },
            |b| ref_name(b.text("Filter")).map(|(_, v)| v),
        ),
        None => BoundBy {
            current: Vec::new(),
            not_current: Vec::new(),
        },
    };
    entry.put("consumer_bound_filters", json!(bound.current));
    if mapping_read {
        entry.put(
            "consumer_bound_filters_not_current",
            json!(bound.not_current),
        );
    }
    let also = not_current_sentence(&bound.not_current, "filter(s)");
    entry.runs_when = if bound.current.is_empty() {
        let none = if mapping_read {
            "No __FilterToConsumerBinding the page mapping establishes as current names this \
             consumer, so nothing current found here invokes it."
        } else {
            "No __FilterToConsumerBinding found by this scan names this consumer, so nothing \
             found here invokes it."
        };
        format!("When invoked, {}. {none}{also}", action.statement)
    } else {
        format!(
            "When invoked, {}. Invoked by filter(s) {}.{also}",
            action.statement,
            bound
                .current
                .iter()
                .map(|f| format!("'{f}'"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
}

fn describe_binding(entry: &mut AsepEntry, rec: &WmiRecord, all: &[WmiRecord], mapping_read: bool) {
    let filter_ref = rec.text("Filter").map(str::to_string);
    let consumer_ref = rec.text("Consumer").map(str::to_string);
    entry.put("binding_filter_ref", json!(filter_ref));
    entry.put("binding_consumer_ref", json!(consumer_ref));

    let filter = ref_name(filter_ref.as_deref());
    let consumer = ref_name(consumer_ref.as_deref());
    let filter_name = filter
        .as_ref()
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "(filter reference unreadable)".to_string());
    let consumer_name = consumer
        .as_ref()
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "(consumer reference unreadable)".to_string());
    entry.entry_name = format!("{filter_name} -> {consumer_name}");
    entry.put(
        "binding_consumer_class",
        json!(consumer.as_ref().map(|(c, _)| c.clone())),
    );

    // Every copy found, best-standing first: the end a binding resolves to is
    // the copy the mapping establishes as current when there is one, never
    // merely the copy at the lowest offset.
    let filter_recs = by_currency(
        filter
            .as_ref()
            .map(|(_, v)| filters_named(all, v))
            .unwrap_or_default(),
        mapping_read,
    );
    let consumer_recs = by_currency(
        consumer
            .as_ref()
            .map(|(c, v)| consumers_named(all, c, v))
            .unwrap_or_default(),
        mapping_read,
    );
    entry.put("binding_filter_resolved", json!(!filter_recs.is_empty()));
    entry.put(
        "binding_consumer_resolved",
        json!(!consumer_recs.is_empty()),
    );
    entry.put(
        "binding_filter_record_offsets",
        json!(filter_recs.iter().map(|r| r.offset).collect::<Vec<_>>()),
    );
    entry.put(
        "binding_consumer_record_offsets",
        json!(consumer_recs.iter().map(|r| r.offset).collect::<Vec<_>>()),
    );

    let mut incomplete: Vec<String> = Vec::new();
    // An end found only as a copy the mapping does not establish as current.
    let mut stale_end = false;
    let trigger = match filter_recs.first() {
        Some(f) => {
            let query = f.text("Query").unwrap_or("(no Query stored)");
            let ns = f
                .text("EventNamespace")
                .unwrap_or("(no EventNamespace stored)");
            entry.put("filter_query", json!(query));
            entry.put("filter_namespace", json!(ns));
            if mapping_read {
                entry.put("binding_filter_record_current", json!(is_current(f)));
                if !is_current(f) {
                    stale_end = true;
                    incomplete.push(format!(
                        "The filter '{filter_name}' this binding names was found only as {} \
                         (offset {:#x}); the trigger shown is taken from that copy, which is \
                         not established to be the one the repository currently holds.",
                        not_current_phrase(f),
                        f.offset
                    ));
                }
            }
            format!("an event matches filter '{filter_name}' ({query:?} in namespace {ns})")
        }
        None => {
            incomplete.push(format!(
                "The filter '{filter_name}' this binding names was not found by the scan, so \
                 what triggers it is not known from this file."
            ));
            format!(
                "an event matches filter '{filter_name}', whose record was not found by this scan"
            )
        }
    };
    let action = match consumer_recs.first() {
        Some(c) => {
            entry.put("binding_consumer_record_class", json!(c.class_name));
            if mapping_read {
                entry.put("binding_consumer_record_current", json!(is_current(c)));
                if !is_current(c) {
                    stale_end = true;
                    incomplete.push(format!(
                        "The consumer '{consumer_name}' this binding names was found only as \
                         {} (offset {:#x}); the action and any command line shown are taken \
                         from that copy, which is not established to be the one the \
                         repository currently holds.",
                        not_current_phrase(c),
                        c.offset
                    ));
                }
            }
            let action = consumer_action(c);
            apply_action(entry, &action);
            format!("WMI {}", action.statement)
        }
        None => {
            let class = consumer
                .as_ref()
                .map(|(c, _)| c.as_str())
                .unwrap_or("an unreadable class");
            incomplete.push(format!(
                "The consumer '{consumer_name}' of class {class} this binding names was not \
                 found by the scan, so what it does is not known from this file."
            ));
            format!(
                "WMI invokes consumer '{consumer_name}' of class {class}, whose record was not \
                 found by this scan"
            )
        }
    };
    if stale_end && is_current(rec) {
        entry.enabled_basis = if matches!(standing(rec), Standing::Indexed { .. }) {
            "WMI subscriptions carry no enabled flag. This binding's record is named by the \
             repository's index (INDEX.BTR), but its filter or consumer was found only as a \
             copy the repository does not establish as current, so that the binding is in \
             force was not established."
                .to_string()
        } else {
            "WMI subscriptions carry no enabled flag. This binding's record \
             is in the repository's current page mapping and its descriptor table lists it, \
             but its filter or consumer was found only as a copy the mapping does not \
             establish as current, so that the binding is in force was not established; the \
             index (INDEX.BTR) was not read."
                .to_string()
        };
    }
    entry.runs_when = format!("When {trigger}, {action}.");
    if !incomplete.is_empty() {
        entry.incomplete_reason = Some(incomplete.join(" "));
        entry.incomplete_code = Some(IncompleteReason::UnresolvedStructure);
    }
}

fn apply_action(entry: &mut AsepEntry, action: &ConsumerAction) {
    entry.image = action.image.clone();
    entry.command = action.command.clone();
    entry.arguments = action.arguments.clone();
    entry.working_dir = action.working_dir.clone();
    // A bare program name is searched for in the consumer's working directory
    // first, under the consumer's own extension rule (`HUNT-244`).
    entry.search_context = crate::normalize::SearchContext {
        rule: action.search_rule,
        working_directory: action.working_dir.clone(),
    };
    entry.split_basis = action.split_basis;
    entry.put("consumer_action", json!(action.statement));
    entry.put("consumer_action_described", json!(action.described));
    if action.image.is_some() || action.command.is_some() {
        entry.observe(
            "executes_code",
            "This consumer starts a process or runs a script when its binding fires.",
        );
    }
}
