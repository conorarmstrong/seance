//! A record-level scan of the WMI CIM repository's `OBJECTS.DATA` for event
//! subscriptions: `__EventFilter`, the event consumers, and the
//! `__FilterToConsumerBinding` that joins one to the other.
//!
//! # What this is, and what it is not
//!
//! The repository is three files: `OBJECTS.DATA` holds the records,
//! `INDEX.BTR` is the B-tree that names them, and `MAPPING*.MAP` translates
//! the logical page numbers the index uses into physical pages of
//! `OBJECTS.DATA`. This module reads `OBJECTS.DATA`, and the mapping when the
//! caller hands it one ([`scan_with_mapping`], parsed by
//! [`crate::wmi_mapping`]); it never reads the index. It reads each page's own
//! descriptor table (8192-byte pages) and recognises the instance records of
//! the subscription classes by the class-name hash every instance record
//! begins with.
//!
//! Without a mapping it walks the physical pages in order: a record that runs
//! past its page cannot be followed, and whether a record found is one the
//! repository currently maps or a superseded copy in a page the mapping no
//! longer points at is not established. With one (HUNT-195) it walks the
//! logical pages in order, reads a spanning record on into the next logical
//! page the mapping names, does not read a continuation page's first bytes as
//! a descriptor table, and labels every record by its page: mapped (with its
//! logical page number) or unmapped -- a free page, whose records are
//! superseded or free-page copies. Every record it emits says which applied.
//!
//! # Where the layout comes from
//!
//! An instance record carries no property names: it is a state-bit array and
//! a run of values whose order and width are fixed by the class definition.
//! Rather than hard-code those layouts, the scan first collects the class
//! definition records present in the same file and reads each class's
//! property table (name, CIM type, index, offset) from them. The two real
//! repositories in the test fixtures each carry two different
//! `ActiveScriptEventConsumer` definitions, so a table typed into the code
//! would have been wrong for one of them.
//!
//! # Format references
//!
//! * Joachim Metz, *WMI repository file format* (libyal/dtformats): page and
//!   descriptor layout, the instance record header (class-name hash, two
//!   FILETIMEs, block size), the class definition record, and the
//!   hash derivation (uppercase class name, UTF-16LE; the reference gives
//!   MD5 on XP/2003 and SHA-256 from Vista onward — a version range this
//!   code has not observed and does not depend on: both forms are tried on
//!   every file, and the corpus showed MD5 on Windows XP and SHA-256 on
//!   Windows 10).
//! * Ballenthin, Graeber, Teodorescu, *Windows Management Instrumentation
//!   (WMI) Offense, Defense, and Forensics* (FireEye, 2015), and the
//!   `flare-wmi` reader it describes, for the same structures.
//!
//! Where the observed bytes disagreed with a reference, the bytes won and the
//! difference is noted at the point of use: the XP record checksum is the
//! ordinary CRC-32 (`crc32fast`), not a zero-initialised variant.

use crate::normalize::split_command;
use md5::{Digest as _, Md5};
use seance_core::secdesc::parse_sid;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Size of one `OBJECTS.DATA` page.
pub const PAGE_SIZE: usize = 8192;

/// Ceiling on how much of `OBJECTS.DATA` is read. The two real files in the
/// corpus are 5 and 24 MB; a repository that has grown past this is reported
/// as capped, with the number.
pub const MAX_OBJECTS_DATA_BYTES: u64 = 512 * 1024 * 1024;

/// Ceiling on instance records kept from one file.
pub const MAX_RECORDS: usize = 4096;

/// Ceiling on strings listed from one record's data block.
pub const MAX_DATA_STRINGS: usize = 64;

/// Ceiling on the length of one decoded string value.
pub const MAX_STRING_BYTES: usize = 65_536;

/// A descriptor table cannot hold more entries than fit in the page.
const MAX_DESCRIPTORS_PER_PAGE: usize = PAGE_SIZE / 16;

/// Class definition chains deeper than this are treated as corrupt.
const MAX_INHERITANCE_DEPTH: usize = 16;

/// The two classes every subscription needs.
pub const CORE_CLASSES: &[&str] = &["__EventFilter", "__FilterToConsumerBinding"];

/// The consumer classes Windows ships. Any other consumer class is picked up
/// from the bindings that name it.
pub const STANDARD_CONSUMER_CLASSES: &[&str] = &[
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
    "NTEventLogEventConsumer",
    "LogFileEventConsumer",
    "SMTPEventConsumer",
];

/// Classes whose instance decoding has been checked against real records.
/// A decoded record of any other class carries a note saying its class had no
/// real instance in the validation corpus. `CommandLineEventConsumer` joined on
/// 2026-09-24 from Windows 7's stock `BVTConsumer` in the Data Leakage
/// repository (`WMI-1` in `documentation/VALIDATION.md`).
pub const VALIDATED_INSTANCE_CLASSES: &[&str] = &[
    "__EventFilter",
    "__FilterToConsumerBinding",
    "NTEventLogEventConsumer",
    "MSFT_UCScenarioControl",
    "CommandLineEventConsumer",
];

/// Which hash the repository uses for class names. Both are tried on every
/// file; the form a record matched under is reported, not inferred from a
/// Windows version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashForm {
    /// SHA-256, 64 hex characters. Observed on the Windows 10 repository
    /// (libyal/dtformats gives it as the form from Vista onward; not
    /// observed here).
    Sha256,
    /// MD5, 32 hex characters. Observed on the Windows XP repository
    /// (libyal/dtformats gives it as the XP / Server 2003 form; Server 2003
    /// not observed here).
    Md5,
}

impl HashForm {
    /// Bytes the hash occupies at the start of a record (UTF-16LE hex).
    pub fn byte_len(self) -> usize {
        match self {
            HashForm::Sha256 => 128,
            HashForm::Md5 => 64,
        }
    }

    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            HashForm::Sha256 => "sha256",
            HashForm::Md5 => "md5",
        }
    }
}

/// How the record was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordProvenance {
    /// The page's descriptor table lists the record.
    AllocatedPageRecord,
    /// The class hash was found in bytes no descriptor on the page points at:
    /// slack, or a page whose table has been rewritten. Such a record is
    /// recovered, not live, and is typed as such downstream.
    UnreferencedBytes,
}

impl RecordProvenance {
    /// Stable string form.
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordProvenance::AllocatedPageRecord => "allocated_record",
            RecordProvenance::UnreferencedBytes => "recovered",
        }
    }
}

/// Outcome of comparing the descriptor's checksum with the record bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumStatus {
    /// The descriptor stores a CRC-32 and it matches the bytes.
    Verified,
    /// The descriptor stores a CRC-32 and it does not match.
    Mismatch { stored: u32, computed: u32 },
    /// The descriptor's checksum field is zero, so nothing was verified.
    /// Decided per descriptor, never per repository: on the complete Lone
    /// Wolf Windows 10 `OBJECTS.DATA`, counted with this scanner's own
    /// descriptor walk, 11,470 of the 11,548 descriptor entries read zero
    /// here and 78 do not (25 within their page, 53 declaring a size past
    /// it) — the 78 lie in table bytes the walk accepts by shape, not in
    /// any record this scanner decodes, and every one of the three
    /// subscription records it does decode there reads zero.
    /// (libyal/dtformats: none stored from Windows 7 onward; only Windows
    /// 10 was observed.) The census is pinned by
    /// `unit::the_lonewolf_descriptor_checksum_field_census_is_what_the_rustdoc_says`,
    /// which runs when `SEANCE_LONEWOLF_OBJECTS_DATA` names the file.
    NotStored,
    /// No descriptor describes this record, so there is nothing to check.
    NotApplicable,
}

impl ChecksumStatus {
    /// Stable string form.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChecksumStatus::Verified => "verified",
            ChecksumStatus::Mismatch { .. } => "mismatch",
            ChecksumStatus::NotStored => "not_stored",
            ChecksumStatus::NotApplicable => "not_applicable",
        }
    }
}

/// Where a property's value came from, per the instance's state bits.
///
/// The class definition's own default-value block uses the same two bits, and
/// reading it settled their meaning: the first bit marks a null, the second
/// marks a value the instance does not store because the class default
/// applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropState {
    /// The instance stores the value.
    Stored,
    /// The instance does not store a value; the class default applies and is
    /// what `value` holds when it could be read.
    ClassDefault,
    /// Null.
    Null,
}

impl PropState {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            PropState::Stored => "stored",
            PropState::ClassDefault => "class_default",
            PropState::Null => "null",
        }
    }
}

/// A decoded property value.
#[derive(Debug, Clone, PartialEq)]
pub enum PropValue {
    Str(String),
    Bool(bool),
    Signed(i64),
    Unsigned(u64),
    Real(f64),
    Bytes(Vec<u8>),
    StrArray(Vec<String>),
    /// The state bits say null.
    Null,
    /// The value could not be read; the reason travels with it.
    Undecoded(String),
}

/// One property of a decoded instance.
#[derive(Debug, Clone)]
pub struct Property {
    pub name: String,
    pub cim_type: String,
    pub state: PropState,
    pub value: PropValue,
}

/// Whether the record's properties were read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeStatus {
    /// Decoded with the class definition at this file offset.
    Decoded { layout_offset: usize },
    /// Recognised by its class hash but not decoded, for the stated reason.
    Undecodable(String),
}

/// One instance record of a subscription class.
#[derive(Debug, Clone)]
pub struct WmiRecord {
    /// Byte offset of the record in the file.
    pub offset: usize,
    /// Record size: the descriptor's, or the block's own size field for an
    /// unreferenced record.
    pub size: usize,
    /// Physical page number.
    pub page: usize,
    /// Descriptor record identifier, when a descriptor lists the record.
    pub record_id: Option<u32>,
    pub provenance: RecordProvenance,
    pub checksum: ChecksumStatus,
    pub hash_form: HashForm,
    /// Class name, from the hash match and confirmed against the record's own
    /// class-name string when the record decoded.
    pub class_name: String,
    /// The two FILETIMEs the record header carries. Public documentation
    /// leaves their individual meanings unknown; both are reported.
    pub filetime_a: u64,
    pub filetime_b: u64,
    /// The descriptor's size runs past the end of the page. The continuation
    /// lives in the next *logical* page, which only the mapping can name.
    pub spans_pages: bool,
    pub properties: Vec<Property>,
    /// `CreatorSID` rendered, when present and well-formed.
    pub creator_sid: Option<String>,
    /// Printable runs in the record's data block, in order. Present whether
    /// or not the record decoded, so an undecodable record still shows what
    /// it holds.
    pub data_strings: Vec<String>,
    pub data_strings_truncated: bool,
    pub decode: DecodeStatus,
    /// Where the record's page sits in the repository's page mapping.
    pub page_state: PageState,
    /// The record ran past its page and was read whole by following the page
    /// mapping to its continuation (HUNT-195).
    pub reassembled: bool,
    /// Whether the repository's index names this record: `Some` only for a
    /// descriptor-listed record in a mapped page once `INDEX.BTR` was read
    /// ([`ScanOutcome::apply_index`], HUNT-195); `None` otherwise.
    pub indexed: Option<bool>,
    /// Anything decoded on documentation rather than corpus observation, or
    /// otherwise worth an examiner's attention.
    pub notes: Vec<String>,
}

/// A physical page's place in the repository's page mapping (HUNT-195).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    /// No mapping file was read, so the page's currency is unknown.
    MappingNotRead,
    /// The mapping names this page as the given logical page, and the page
    /// opens with a descriptor table.
    Mapped { logical: usize },
    /// The mapping names this page as the given logical page, which holds the
    /// continuation of a record begun on an earlier logical page. It has no
    /// descriptor table of its own.
    Continuation { logical: usize },
    /// No logical page maps here: the page is free, and any record on it is a
    /// superseded or free-page copy, not current repository data.
    Unmapped,
    /// A mapping was read, but the page lies past every page it accounts for:
    /// the trailing part-page of a file whose length is not a whole number of
    /// pages. No entry of the mapping covers it.
    BeyondMapping,
}

impl PageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PageState::MappingNotRead => "mapping_not_read",
            PageState::Mapped { .. } => "mapped",
            PageState::Continuation { .. } => "continuation",
            PageState::Unmapped => "unmapped",
            PageState::BeyondMapping => "beyond_mapping",
        }
    }
}

impl WmiRecord {
    /// A string property's value, when stored or defaulted.
    pub fn text(&self, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .and_then(|p| match &p.value {
                PropValue::Str(s) => Some(s.as_str()),
                _ => None,
            })
    }
}

/// One property as the class definition declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropDef {
    pub name: String,
    /// CIM type with the 0x2000 array flag.
    pub cim_type: u32,
    /// Position in the state-bit array, counting inherited properties.
    pub index: u16,
    /// Offset in the instance's value area.
    pub offset: u32,
}

/// A class definition record, as far as the scan reads it.
#[derive(Debug, Clone)]
pub struct ClassLayout {
    pub name: String,
    pub superclass: String,
    /// File offset of the definition record.
    pub offset: usize,
    /// The class's own properties, sorted by index.
    pub own: Vec<PropDef>,
    /// The class's default-value block: state bits and values.
    default_values: Vec<u8>,
    /// The definition's heap, which the default values reference.
    heap: Vec<u8>,
}

/// What the scan covered, in numbers.
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    pub bytes_scanned: usize,
    pub pages: usize,
    /// Bytes past the last whole page, which no descriptor table describes.
    pub trailing_bytes: usize,
    pub pages_with_descriptor_table: usize,
    pub descriptor_records: usize,
    /// Descriptor-listed records whose declared size runs past their page.
    /// Their continuation lives in the next *logical* page, which only the
    /// mapping can name. Without a mapping they are never tried as class
    /// definitions, so a class whose only definition is such a record has no
    /// layout and its instances are reported undecodable for want of one;
    /// with one, each that `descriptors_reassembled` counts was read whole and
    /// tried. Counted in `descriptor_records`.
    pub descriptors_spanning_pages: usize,
    /// The records tried as class definitions: those whose bytes lie within
    /// their page, plus those reassembled through the mapping.
    pub descriptors_tried_as_class_definitions: usize,
    pub class_definitions_seen: usize,
    /// Occurrences of a target class hash anywhere in the file.
    pub signature_hits: usize,
    /// Hits inside a descriptor-listed record that does not start there (a
    /// key path naming the class, typically). Not instances.
    pub hits_inside_other_records: usize,
    /// Hits in bytes no descriptor points at.
    pub unreferenced_hits: usize,
    /// Descriptor-listed records that begin with a target class hash.
    pub instance_records_matched: usize,
    pub records_decoded: usize,
    pub records_undecodable: usize,
    /// Matched records that run past their page and were not read whole:
    /// no mapping was read, or their continuation could not be followed.
    /// A record reassembled through the mapping is not counted.
    pub records_spanning_pages: usize,
    /// The record ceiling was reached.
    pub capped: bool,
    pub cap_note: Option<String>,
    pub classes_scanned: Vec<String>,
    pub classes_added_from_bindings: Vec<String>,
    /// Target classes with no definition record in the file.
    pub classes_without_definition: Vec<String>,
    /// A page mapping was supplied and the pages were walked in logical
    /// order through it (HUNT-195). The fields below are zero without one.
    pub mapping_used: bool,
    /// Logical pages the mapping lists.
    pub logical_pages: usize,
    /// Physical pages some logical page maps to.
    pub pages_mapped: usize,
    /// Mapped pages that continue a record begun on an earlier logical page;
    /// their first bytes are record data and are not read as a table.
    pub pages_continuation: usize,
    /// Physical pages no logical page maps to (the free pages).
    pub pages_unmapped: usize,
    /// Logical pages the mapping places past the end of the file.
    pub mapped_pages_beyond_file: usize,
    /// Page-spanning descriptors whose continuation was followed through the
    /// mapping and whose record was read whole.
    pub descriptors_reassembled: usize,
    /// Page-spanning descriptors that could not be reassembled: in an
    /// unmapped page, or running past the mapping or the file.
    pub descriptors_spanning_unresolved: usize,
    /// Descriptor-listed records in unmapped pages.
    pub descriptors_in_unmapped_pages: usize,
    /// Subscription-class records found in unmapped pages. One a descriptor
    /// table lists is published as a superseded copy; one no descriptor table
    /// lists (unreferenced bytes) as recovered residue.
    pub records_in_unmapped_pages: usize,
    /// Reassembled page-spanning descriptors whose stored CRC-32 matches the
    /// bytes read through the mapping (XP stores one; Windows 7 onward store
    /// zero, and those are counted in neither field).
    pub reassembled_checksums_verified: usize,
    /// Reassembled page-spanning descriptors whose stored CRC-32 does not
    /// match the bytes read through the mapping.
    pub reassembled_checksums_mismatched: usize,
    /// `INDEX.BTR` was read and walked from its root (HUNT-195).
    pub index_read: bool,
    /// Data references the index tree names.
    pub index_data_references: usize,
    pub index_pages_visited: usize,
    /// Descriptor-listed records in mapped pages that the index does not name.
    pub descriptors_listed_not_indexed: usize,
    /// Subscription-class records the index names.
    pub records_indexed: usize,
    /// Subscription-class records a mapped page's descriptor table lists and
    /// the index does not name.
    pub records_listed_not_indexed: usize,
}

/// Everything one scan produced.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub records: Vec<WmiRecord>,
    pub summary: ScanSummary,
    /// Class definitions found, by class name. A name can carry more than one
    /// layout when the file holds more than one definition of it.
    pub layouts: BTreeMap<String, Vec<ClassLayout>>,
    /// The mapping file the scan walked through and its sequence number, set
    /// by the caller that chose it; `None` when no mapping was used.
    pub mapping_file: Option<(String, u32)>,
    /// Every descriptor-listed record in a page the mapping names as a
    /// logical page of its own (not a continuation, not an unmapped page):
    /// (logical page, record id, record size), the key `INDEX.BTR` names a
    /// record by. Empty when no mapping was used (HUNT-195).
    pub listed_descriptors: Vec<crate::wmi_index::DataRef>,
    /// What the index beside the file came to, set by the caller through
    /// [`ScanOutcome::apply_index`].
    pub index: crate::wmi_index::IndexRead,
}

impl WmiRecord {
    /// The key the index names this record by: its starting logical page, its
    /// descriptor id and its size. `None` for a record that is not a
    /// descriptor-listed record in a mapped page.
    pub fn index_key(&self) -> Option<crate::wmi_index::DataRef> {
        match (self.page_state, &self.provenance, self.record_id) {
            (PageState::Mapped { logical }, RecordProvenance::AllocatedPageRecord, Some(id)) => {
                Some((logical as u32, id, self.size as u32))
            }
            _ => None,
        }
    }
}

impl ScanOutcome {
    /// Record what the index came to and count what it says of this scan.
    pub fn apply_index(&mut self, index: crate::wmi_index::IndexRead) {
        if let Some(set) = index.set() {
            let s = &mut self.summary;
            s.index_read = true;
            s.index_data_references = set.refs.len();
            s.index_pages_visited = set.pages_visited;
            s.descriptors_listed_not_indexed = self
                .listed_descriptors
                .iter()
                .filter(|k| !set.refs.contains(k))
                .count();
            for rec in &mut self.records {
                rec.indexed = rec.index_key().map(|k| set.refs.contains(&k));
            }
            s.records_indexed = self
                .records
                .iter()
                .filter(|r| r.indexed == Some(true))
                .count();
            s.records_listed_not_indexed = self
                .records
                .iter()
                .filter(|r| r.indexed == Some(false))
                .count();
        }
        self.index = index;
    }
}

/// Scan a whole `OBJECTS.DATA` image with no page mapping.
pub fn scan(buf: &[u8]) -> ScanOutcome {
    scan_with_mapping(buf, None)
}

/// Scan a whole `OBJECTS.DATA` image, walking it through the repository's
/// page mapping (`OBJECTS.DATA`'s section of the active `MAPPINGn.MAP`, or
/// XP's `OBJECTS.MAP`) when one is given.
pub fn scan_with_mapping(buf: &[u8], mapping: Option<&crate::wmi_mapping::PageMap>) -> ScanOutcome {
    let mut summary = ScanSummary {
        bytes_scanned: buf.len(),
        pages: buf.len() / PAGE_SIZE,
        trailing_bytes: buf.len() % PAGE_SIZE,
        ..ScanSummary::default()
    };

    let pages = match mapping {
        Some(map) => walk_mapped(buf, map, &mut summary),
        None => PageWalk {
            tables: (0..summary.pages)
                .map(|page| descriptor_table(buf, page))
                .collect(),
            states: vec![PageState::MappingNotRead; summary.pages],
            continuations: HashMap::new(),
        },
    };
    summary.pages_with_descriptor_table = pages.tables.iter().filter(|t| !t.is_empty()).count();
    summary.descriptor_records = pages.tables.iter().map(Vec::len).sum();

    let mut layouts: BTreeMap<String, Vec<ClassLayout>> = BTreeMap::new();
    for table in &pages.tables {
        for d in table {
            let whole;
            let bytes: &[u8] = if d.spans_pages {
                summary.descriptors_spanning_pages += 1;
                match pages.continuations.get(&d.offset) {
                    Some(cont) => {
                        whole = assemble(buf, d, cont);
                        // The repository's own check on the reassembly, where
                        // it stores one (XP): the CRC-32 of the whole record.
                        if d.checksum != 0 {
                            if crc32fast::hash(&whole) == d.checksum {
                                summary.reassembled_checksums_verified += 1;
                            } else {
                                summary.reassembled_checksums_mismatched += 1;
                            }
                        }
                        &whole
                    }
                    None => continue,
                }
            } else {
                &buf[d.offset..d.offset + d.size]
            };
            summary.descriptors_tried_as_class_definitions += 1;
            if let Some(layout) = parse_class_definition(bytes, d.offset) {
                summary.class_definitions_seen += 1;
                let slot = layouts.entry(layout.name.clone()).or_default();
                if !slot
                    .iter()
                    .any(|l| l.superclass == layout.superclass && l.own == layout.own)
                {
                    slot.push(layout);
                }
            }
        }
    }

    let mut targets: BTreeSet<String> = CORE_CLASSES
        .iter()
        .chain(STANDARD_CONSUMER_CLASSES)
        .map(|s| s.to_string())
        .collect();
    let mut records = Vec::new();
    let first_round: Vec<String> = targets.iter().cloned().collect();
    scan_for_classes(
        buf,
        &pages,
        &layouts,
        &first_round,
        &mut records,
        &mut summary,
    );

    // A binding names its consumer's class. Any class not already scanned for
    // is scanned for now, so a consumer of a non-standard class is not missed
    // because nobody typed its name into a table.
    let mut extra: Vec<String> = Vec::new();
    for rec in &records {
        if !rec
            .class_name
            .eq_ignore_ascii_case("__FilterToConsumerBinding")
        {
            continue;
        }
        if let Some(path) = rec.text("Consumer") {
            if let Some(r) = parse_object_path(path) {
                if !targets.iter().any(|t| t.eq_ignore_ascii_case(&r.class))
                    && !extra.iter().any(|e| e.eq_ignore_ascii_case(&r.class))
                {
                    extra.push(r.class);
                }
            }
        }
    }
    if !extra.is_empty() {
        scan_for_classes(buf, &pages, &layouts, &extra, &mut records, &mut summary);
        summary.classes_added_from_bindings = extra.clone();
        targets.extend(extra);
    }

    summary.classes_scanned = targets.iter().cloned().collect();
    summary.classes_without_definition = targets
        .iter()
        .filter(|t| !layouts.keys().any(|k| k.eq_ignore_ascii_case(t)))
        .cloned()
        .collect();
    records.sort_by_key(|r| r.offset);

    let mut listed_descriptors = Vec::new();
    for (p, table) in pages.tables.iter().enumerate() {
        if let PageState::Mapped { logical } = pages.states[p] {
            listed_descriptors.extend(table.iter().map(|d| (logical as u32, d.id, d.size as u32)));
        }
    }

    ScanOutcome {
        records,
        summary,
        layouts,
        mapping_file: None,
        listed_descriptors,
        index: crate::wmi_index::IndexRead::default(),
    }
}

/// The pages as the scan reads them: each physical page's descriptor table
/// (empty for a continuation page), its place in the mapping, and, for each
/// page-spanning record the mapping lets be followed, the physical pages its
/// continuation occupies in order.
struct PageWalk {
    tables: Vec<Vec<Descriptor>>,
    states: Vec<PageState>,
    continuations: HashMap<usize, Vec<usize>>,
}

/// Walk `OBJECTS.DATA` in logical page order through `map` (HUNT-195).
///
/// Each mapped page not already claimed as a continuation has its descriptor
/// table read. A descriptor whose record runs past its page claims the
/// following logical pages, as many as its size needs, as its continuation;
/// those pages are record data and are not read as tables. Physical pages no
/// logical page maps to are read as before and marked unmapped; a spanning
/// record there cannot be followed, since a free page has no next logical page.
fn walk_mapped(
    buf: &[u8],
    map: &crate::wmi_mapping::PageMap,
    summary: &mut ScanSummary,
) -> PageWalk {
    let npages = summary.pages;
    let mut states = vec![PageState::Unmapped; npages];
    let mut tables: Vec<Vec<Descriptor>> = vec![Vec::new(); npages];
    let mut continuations: HashMap<usize, Vec<usize>> = HashMap::new();
    summary.mapping_used = true;
    summary.logical_pages = map.logical.len();

    for (logical, &p) in map.logical.iter().enumerate() {
        if p == crate::wmi_mapping::UNMAPPED {
            continue;
        }
        match states.get_mut(p as usize) {
            Some(state) => {
                if *state == PageState::Unmapped {
                    *state = PageState::Mapped { logical };
                }
            }
            None => summary.mapped_pages_beyond_file += 1,
        }
    }

    for logical in 0..map.logical.len() {
        let Some(p) = map.physical(logical).filter(|&p| p < npages) else {
            continue;
        };
        if matches!(states[p], PageState::Continuation { .. }) {
            continue;
        }
        let table = descriptor_table(buf, p);
        for d in table.iter().filter(|d| d.spans_pages) {
            let extra = (d.offset % PAGE_SIZE + d.size - 1) / PAGE_SIZE;
            let follow: Option<Vec<usize>> = (1..=extra)
                .map(|k| {
                    map.physical(logical + k)
                        .filter(|&q| q < npages && matches!(states[q], PageState::Mapped { .. }))
                })
                .collect();
            match follow {
                Some(cont) => {
                    for (k, &q) in cont.iter().enumerate() {
                        states[q] = PageState::Continuation {
                            logical: logical + k + 1,
                        };
                    }
                    summary.descriptors_reassembled += 1;
                    continuations.insert(d.offset, cont);
                }
                None => summary.descriptors_spanning_unresolved += 1,
            }
        }
        tables[p] = table;
    }

    for p in 0..npages {
        if states[p] == PageState::Unmapped {
            let table = descriptor_table(buf, p);
            summary.descriptors_in_unmapped_pages += table.len();
            summary.descriptors_spanning_unresolved +=
                table.iter().filter(|d| d.spans_pages).count();
            tables[p] = table;
        }
    }
    summary.pages_unmapped = states.iter().filter(|s| **s == PageState::Unmapped).count();
    summary.pages_continuation = states
        .iter()
        .filter(|s| matches!(s, PageState::Continuation { .. }))
        .count();
    summary.pages_mapped = npages - summary.pages_unmapped;
    PageWalk {
        tables,
        states,
        continuations,
    }
}

/// A page-spanning record read whole: its bytes on its own page, then each
/// continuation page in logical order, up to the descriptor's size.
fn assemble(buf: &[u8], d: &Descriptor, cont: &[usize]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.size);
    out.extend_from_slice(&buf[d.offset..d.offset + d.available]);
    for &q in cont {
        let need = d.size - out.len();
        let start = q * PAGE_SIZE;
        out.extend_from_slice(&buf[start..start + need.min(PAGE_SIZE)]);
    }
    out
}

/// One entry of a page's descriptor table.
#[derive(Debug, Clone)]
struct Descriptor {
    id: u32,
    /// Absolute file offset of the record.
    offset: usize,
    /// Declared size.
    size: usize,
    /// Bytes of the record that lie in this page.
    available: usize,
    checksum: u32,
    spans_pages: bool,
}

fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    buf.get(at..at.checked_add(4)?)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le_u16(buf: &[u8], at: usize) -> Option<u16> {
    buf.get(at..at.checked_add(2)?)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le_u64(buf: &[u8], at: usize) -> Option<u64> {
    buf.get(at..at.checked_add(8)?)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read a page's descriptor table: 16-byte entries (id, offset within the
/// page, size, CRC-32) up to the first all-zero entry. A malformed entry ends
/// the table. Entries are not in offset order (a freed slot is reused), so a
/// record is checked against the whole table's extent once that is known: one
/// that would start inside the table is dropped.
fn descriptor_table(buf: &[u8], page: usize) -> Vec<Descriptor> {
    let base = page * PAGE_SIZE;
    let mut out = Vec::new();
    for i in 0..MAX_DESCRIPTORS_PER_PAGE {
        let at = base + i * 16;
        let (Some(id), Some(off), Some(size), Some(crc)) = (
            le_u32(buf, at),
            le_u32(buf, at + 4),
            le_u32(buf, at + 8),
            le_u32(buf, at + 12),
        ) else {
            break;
        };
        if id == 0 {
            break;
        }
        let off = off as usize;
        let size = size as usize;
        if size == 0 || off >= PAGE_SIZE {
            break;
        }
        let available = size.min(PAGE_SIZE - off);
        out.push(Descriptor {
            id,
            offset: base + off,
            size,
            available,
            checksum: crc,
            spans_pages: off + size > PAGE_SIZE,
        });
    }
    let table_end = base + (out.len() + 1) * 16;
    out.retain(|d| d.offset >= table_end);
    out
}

/// The record's hash string for a class name, in one hash form.
fn class_signature(name: &str, form: HashForm) -> Vec<u8> {
    let upper: Vec<u8> = name
        .to_uppercase()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let hex = match form {
        HashForm::Sha256 => {
            let mut h = Sha256::new();
            h.update(&upper);
            hex_upper(&h.finalize())
        }
        HashForm::Md5 => {
            let mut h = Md5::new();
            h.update(&upper);
            hex_upper(&h.finalize())
        }
    };
    hex.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn is_hex_upper(b: u8) -> bool {
    b.is_ascii_digit() || (b'A'..=b'F').contains(&b)
}

/// Every offset at which one of the signatures occurs.
fn find_signatures(
    buf: &[u8],
    sigs: &HashMap<Vec<u8>, (String, HashForm)>,
) -> Vec<(usize, String, HashForm)> {
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i + 64 <= buf.len() {
        // Cheap gate: a UTF-16LE hex string starts with hex, NUL, hex, NUL.
        if !(is_hex_upper(buf[i]) && buf[i + 1] == 0 && is_hex_upper(buf[i + 2]) && buf[i + 3] == 0)
        {
            i += 1;
            continue;
        }
        let mut matched = None;
        if let Some(hit) = sigs.get(&buf[i..i + 64]) {
            matched = Some((hit.0.clone(), hit.1));
        } else if i + 128 <= buf.len() {
            if let Some(hit) = sigs.get(&buf[i..i + 128]) {
                matched = Some((hit.0.clone(), hit.1));
            }
        }
        match matched {
            Some((class, form)) => {
                let len = form.byte_len();
                hits.push((i, class, form));
                i += len;
            }
            None => i += 2,
        }
    }
    hits
}

/// Scan for the instance records of the named classes and append what is found.
fn scan_for_classes(
    buf: &[u8],
    pages: &PageWalk,
    layouts: &BTreeMap<String, Vec<ClassLayout>>,
    classes: &[String],
    records: &mut Vec<WmiRecord>,
    summary: &mut ScanSummary,
) {
    let mut sigs: HashMap<Vec<u8>, (String, HashForm)> = HashMap::new();
    for class in classes {
        for form in [HashForm::Sha256, HashForm::Md5] {
            sigs.insert(class_signature(class, form), (class.clone(), form));
        }
    }

    // A page past those the walk covers is the trailing part-page. When a
    // mapping was read, no entry of it covers that page (HUNT-195).
    let past_the_pages = if summary.mapping_used {
        PageState::BeyondMapping
    } else {
        PageState::MappingNotRead
    };
    for (offset, class, form) in find_signatures(buf, &sigs) {
        summary.signature_hits += 1;
        let page = offset / PAGE_SIZE;
        let page_state = pages.states.get(page).copied().unwrap_or(past_the_pages);
        let table = pages.tables.get(page).map(Vec::as_slice).unwrap_or(&[]);
        let starts_here = table.iter().find(|d| d.offset == offset);
        // A continuation page is the inside of a record begun on an earlier
        // logical page.
        let inside_other = matches!(page_state, PageState::Continuation { .. })
            || table
                .iter()
                .any(|d| d.offset < offset && offset < d.offset + d.available);

        let whole;
        let (bytes, descriptor, reassembled): (&[u8], _, _) = match starts_here {
            Some(d) => {
                summary.instance_records_matched += 1;
                match pages.continuations.get(&d.offset) {
                    Some(cont) => {
                        whole = assemble(buf, d, cont);
                        (&whole, Some(d), Some(cont))
                    }
                    None => (&buf[d.offset..d.offset + d.available], Some(d), None),
                }
            }
            None if inside_other => {
                summary.hits_inside_other_records += 1;
                continue;
            }
            None => {
                summary.unreferenced_hits += 1;
                let page_end = ((page + 1) * PAGE_SIZE).min(buf.len());
                (&buf[offset..page_end], None, None)
            }
        };

        if records.len() >= MAX_RECORDS {
            summary.capped = true;
            summary.cap_note = Some(format!(
                "The record ceiling of {MAX_RECORDS} was reached; instance records past it \
                 were not decoded and the counts above are lower bounds."
            ));
            return;
        }

        let mut rec = decode_record(
            bytes,
            offset,
            page,
            &class,
            form,
            descriptor,
            reassembled.is_some(),
            layouts,
        );
        if descriptor.is_some_and(|d| d.spans_pages) && reassembled.is_none() {
            summary.records_spanning_pages += 1;
        }
        rec.page_state = page_state;
        if let Some(cont) = reassembled {
            rec.notes.push(format!(
                "The record runs past physical page {page}; it was read whole by following \
                 the page mapping to physical page{} {} (the next logical page{}).",
                if cont.len() == 1 { "" } else { "s" },
                cont.iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                if cont.len() == 1 { "" } else { "s" },
            ));
        }
        if page_state == PageState::Unmapped {
            summary.records_in_unmapped_pages += 1;
            rec.notes.push(format!(
                "Physical page {page} is mapped to no logical page by the repository's page \
                 mapping: it is a free page, so this record is a superseded or free-page copy, \
                 not one the repository currently holds. It is reported because a superseded \
                 subscription is itself a lead."
            ));
        }
        if !VALIDATED_INSTANCE_CLASSES
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&rec.class_name))
            && matches!(rec.decode, DecodeStatus::Decoded { .. })
        {
            rec.notes.push(format!(
                "No {} instance existed in the repositories this decoder was validated \
                 against. Its layout is read from this file's own class definition; the \
                 decoder itself is validated on __EventFilter, __FilterToConsumerBinding, \
                 NTEventLogEventConsumer, CommandLineEventConsumer and MSFT_UCScenarioControl \
                 instances in three real repositories (Windows 10, Windows 7 and Windows XP).",
                rec.class_name
            ));
        }
        match rec.decode {
            DecodeStatus::Decoded { .. } => summary.records_decoded += 1,
            DecodeStatus::Undecodable(_) => summary.records_undecodable += 1,
        }
        records.push(rec);
    }
}

/// Decode one instance record, or explain why it could not be.
#[allow(clippy::too_many_arguments)]
fn decode_record(
    bytes: &[u8],
    offset: usize,
    page: usize,
    class: &str,
    form: HashForm,
    descriptor: Option<&Descriptor>,
    whole: bool,
    layouts: &BTreeMap<String, Vec<ClassLayout>>,
) -> WmiRecord {
    let hlen = form.byte_len();
    let filetime_a = le_u64(bytes, hlen).unwrap_or(0);
    let filetime_b = le_u64(bytes, hlen + 8).unwrap_or(0);
    let block_declared = le_u32(bytes, hlen + 16).map(|v| v as usize);

    let (size, checksum) = match descriptor {
        Some(d) => {
            let status = if d.checksum == 0 {
                ChecksumStatus::NotStored
            } else if d.spans_pages && !whole {
                ChecksumStatus::NotApplicable
            } else {
                let computed = crc32fast::hash(bytes);
                if computed == d.checksum {
                    ChecksumStatus::Verified
                } else {
                    ChecksumStatus::Mismatch {
                        stored: d.checksum,
                        computed,
                    }
                }
            };
            (d.size, status)
        }
        None => (
            block_declared.map(|b| hlen + 16 + b).unwrap_or(bytes.len()),
            ChecksumStatus::NotApplicable,
        ),
    };

    let mut rec = WmiRecord {
        offset,
        size,
        page,
        record_id: descriptor.map(|d| d.id),
        provenance: if descriptor.is_some() {
            RecordProvenance::AllocatedPageRecord
        } else {
            RecordProvenance::UnreferencedBytes
        },
        checksum,
        hash_form: form,
        class_name: class.to_string(),
        filetime_a,
        filetime_b,
        spans_pages: descriptor.is_some_and(|d| d.spans_pages),
        properties: Vec::new(),
        creator_sid: None,
        data_strings: Vec::new(),
        data_strings_truncated: false,
        decode: DecodeStatus::Undecodable(String::new()),
        page_state: PageState::MappingNotRead,
        reassembled: whole && descriptor.is_some_and(|d| d.spans_pages),
        indexed: None,
        notes: Vec::new(),
    };

    let block_start = hlen + 16;
    let strings_from = block_start.min(bytes.len());
    let (strings, truncated) = printable_runs(&bytes[strings_from..]);
    rec.data_strings = strings;
    rec.data_strings_truncated = truncated;

    let block = match block_declared {
        Some(declared) if block_start + declared <= bytes.len() => {
            &bytes[block_start..block_start + declared]
        }
        _ if rec.spans_pages => {
            rec.decode = DecodeStatus::Undecodable(format!(
                "The descriptor's size ({} bytes) runs past the end of physical page {}; the \
                 continuation lies in the next logical page, which only the page mapping \
                 names, and it was not read or could not be followed, so only the {} bytes \
                 on this page were read and the instance block was not decoded.",
                size,
                page,
                bytes.len()
            ));
            return rec;
        }
        Some(declared) => {
            rec.decode = DecodeStatus::Undecodable(format!(
                "The instance block declares {declared} bytes but only {} are present.",
                bytes.len().saturating_sub(block_start)
            ));
            return rec;
        }
        None => {
            rec.decode = DecodeStatus::Undecodable(
                "The record is shorter than the instance header (hash, two FILETIMEs and a \
                 block size)."
                    .to_string(),
            );
            return rec;
        }
    };

    let candidates: Vec<&ClassLayout> = layouts
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(class))
        .flat_map(|(_, v)| v.iter())
        .collect();
    if candidates.is_empty() {
        rec.decode = DecodeStatus::Undecodable(format!(
            "No class definition record for {class} was found in this file by the record \
             scan, so the instance's property layout is unknown. The strings the record \
             holds are listed without attribution to properties."
        ));
        return rec;
    }

    let mut verified: Vec<(usize, Vec<Property>, Vec<String>)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for layout in candidates {
        match decode_instance_block(block, class, layout, layouts) {
            Ok((props, notes)) => verified.push((layout.offset, props, notes)),
            Err(reason) => failures.push(format!("definition at {:#x}: {reason}", layout.offset)),
        }
    }
    match verified.len() {
        0 => {
            rec.decode = DecodeStatus::Undecodable(format!(
                "The instance block did not verify against any class definition of {class} \
                 in this file ({}).",
                failures.join("; ")
            ));
        }
        1 => {
            let (layout_offset, props, notes) = verified.remove(0);
            rec.creator_sid = creator_sid(&props);
            rec.properties = props;
            rec.notes.extend(notes);
            rec.decode = DecodeStatus::Decoded { layout_offset };
        }
        _ => {
            // More than one definition fits. Identical decodes are one answer;
            // different ones are an ambiguity the record must carry.
            let first = &verified[0];
            let all_same = verified.iter().all(|(_, p, _)| same_values(p, &first.1));
            if all_same {
                let (layout_offset, props, notes) = verified.remove(0);
                rec.creator_sid = creator_sid(&props);
                rec.properties = props;
                rec.notes.extend(notes);
                rec.notes.push(format!(
                    "{} definitions of {class} in this file fit the record and decode it \
                     identically.",
                    verified.len() + 1
                ));
                rec.decode = DecodeStatus::Decoded { layout_offset };
            } else {
                rec.decode = DecodeStatus::Undecodable(format!(
                    "{} definitions of {class} in this file fit the record and decode it \
                     differently, so no single reading is reported. The strings the record \
                     holds are listed without attribution.",
                    verified.len()
                ));
            }
        }
    }
    rec
}

fn same_values(a: &[Property], b: &[Property]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.name == y.name && x.state == y.state && x.value == y.value)
}

fn creator_sid(props: &[Property]) -> Option<String> {
    props
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case("CreatorSID"))
        .and_then(|p| match &p.value {
            PropValue::Bytes(b) => parse_sid(b, 0).ok().map(|(sid, _)| sid.to_string()),
            _ => None,
        })
}

/// The complete property list of a class: its own and its ancestors'.
struct FullLayout {
    props: Vec<PropDef>,
    total_props: usize,
    values_len: usize,
    unresolved_parents: Vec<String>,
}

fn full_layout(
    leaf: &ClassLayout,
    layouts: &BTreeMap<String, Vec<ClassLayout>>,
) -> Result<FullLayout, String> {
    let mut props: Vec<PropDef> = Vec::new();
    let mut unresolved = Vec::new();
    let mut current: Option<&ClassLayout> = Some(leaf);
    let mut depth = 0;
    while let Some(cls) = current {
        props.extend(cls.own.iter().cloned());
        if cls.superclass.is_empty() {
            break;
        }
        depth += 1;
        if depth > MAX_INHERITANCE_DEPTH {
            return Err(format!(
                "the inheritance chain is deeper than {MAX_INHERITANCE_DEPTH} classes"
            ));
        }
        current = layouts
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&cls.superclass))
            .and_then(|(_, v)| v.first());
        if current.is_none() {
            unresolved.push(cls.superclass.clone());
        }
    }
    props.sort_by_key(|p| p.index);
    props.dedup_by_key(|p| p.index);
    let total_props = props
        .iter()
        .map(|p| usize::from(p.index) + 1)
        .max()
        .unwrap_or(0);
    let mut values_len = 0usize;
    for p in &props {
        let size = cim_value_size(p.cim_type).ok_or_else(|| {
            format!(
                "property {} has CIM type {:#x}, whose value width this build does not know",
                p.name, p.cim_type
            )
        })?;
        values_len = values_len.max(p.offset as usize + size);
    }
    Ok(FullLayout {
        props,
        total_props,
        values_len,
        unresolved_parents: unresolved,
    })
}

/// Width of a property's slot in the value area. Widths marked here as
/// observed were confirmed by the offsets in real class definitions; the rest
/// follow the format documentation.
fn cim_value_size(cim_type: u32) -> Option<usize> {
    if cim_type & 0x2000 != 0 {
        return Some(4); // array: heap offset (observed)
    }
    Some(match cim_type & 0xfff {
        2 => 2,   // sint16
        3 => 4,   // sint32 (observed)
        4 => 4,   // real32
        5 => 8,   // real64
        8 => 4,   // string: heap offset (observed)
        11 => 2,  // boolean (observed)
        13 => 4,  // object: heap offset
        16 => 1,  // sint8
        17 => 1,  // uint8
        18 => 2,  // uint16 (observed)
        19 => 4,  // uint32 (observed)
        20 => 8,  // sint64
        21 => 8,  // uint64 (observed)
        101 => 4, // datetime: heap offset
        102 => 4, // reference: heap offset (observed)
        103 => 2, // char16
        _ => return None,
    })
}

fn cim_type_name(cim_type: u32) -> String {
    let base = match cim_type & 0xfff {
        2 => "sint16",
        3 => "sint32",
        4 => "real32",
        5 => "real64",
        8 => "string",
        11 => "boolean",
        13 => "object",
        16 => "sint8",
        17 => "uint8",
        18 => "uint16",
        19 => "uint32",
        20 => "sint64",
        21 => "uint64",
        101 => "datetime",
        102 => "reference",
        103 => "char16",
        _ => return format!("cim_type_{cim_type:#x}"),
    };
    if cim_type & 0x2000 != 0 {
        format!("{base}[]")
    } else {
        base.to_string()
    }
}

/// Decode an instance block against one class definition.
///
/// The block is verified end to end before any value is trusted: the value
/// area computed from the layout must be followed by a qualifier block, the
/// dynamic-block type byte and a heap whose declared length ends exactly at
/// the block's end, and the heap's class-name string must be the class the
/// hash named. A layout that does not fit is rejected, not approximated.
fn decode_instance_block(
    block: &[u8],
    class: &str,
    layout: &ClassLayout,
    layouts: &BTreeMap<String, Vec<ClassLayout>>,
) -> Result<(Vec<Property>, Vec<String>), String> {
    let full = full_layout(layout, layouts)?;
    let class_name_off = le_u32(block, 4).ok_or("block shorter than its header")? as usize;
    let state_bytes = (2 * full.total_props).div_ceil(8);
    let values_start = 9 + state_bytes;
    let values_end = values_start + full.values_len;
    let qual_size = le_u32(block, values_end).ok_or("value area runs past the block")? as usize;
    if qual_size < 4 {
        return Err("qualifier block size below its own 4-byte header".to_string());
    }
    let p = values_end + qual_size;
    let dyn_type = *block.get(p).ok_or("qualifier block runs past the block")?;
    match dyn_type {
        1 => {}
        2 => {
            return Err(
                "the instance uses the dynamic-property form (type 2), which this build \
                 does not decode"
                    .to_string(),
            )
        }
        other => return Err(format!("unexpected dynamic block type {other:#x}")),
    }
    let heap_len_raw = le_u32(block, p + 1).ok_or("heap length runs past the block")?;
    if heap_len_raw & 0x8000_0000 == 0 {
        return Err("heap length lacks its marker bit".to_string());
    }
    let heap_len = (heap_len_raw & 0x7fff_ffff) as usize;
    let heap_start = p + 5;
    if heap_start + heap_len != block.len() {
        return Err(format!(
            "heap of {heap_len} bytes at {heap_start:#x} does not end at the block's end \
             ({:#x})",
            block.len()
        ));
    }
    let heap = &block[heap_start..];
    let (heap_class, _) = heap_string(heap, class_name_off)
        .ok_or("class-name offset does not point at a string in the heap")?;
    if !heap_class.eq_ignore_ascii_case(class) {
        return Err(format!(
            "the heap names class {heap_class:?}, not {class:?}"
        ));
    }

    let state_bits = &block[9..values_start];
    let values = &block[values_start..values_end];
    let mut notes = Vec::new();
    if !full.unresolved_parents.is_empty() {
        notes.push(format!(
            "The definition of superclass {} was not found in this file, so properties \
             inherited from it are not named; the class's own properties decode unaffected.",
            full.unresolved_parents.join(", ")
        ));
    }
    let mut props = Vec::with_capacity(full.props.len());
    for def in &full.props {
        let i = usize::from(def.index);
        let bit = |n: usize| (state_bits.get(n / 8).copied().unwrap_or(0) >> (n % 8)) & 1 == 1;
        let is_null = bit(2 * i);
        let is_default = bit(2 * i + 1);
        let (state, value) = if is_null {
            (PropState::Null, PropValue::Null)
        } else if is_default {
            (
                PropState::ClassDefault,
                class_default_value(def, layout, layouts, &mut notes),
            )
        } else {
            (PropState::Stored, read_value(def, values, heap, &mut notes))
        };
        props.push(Property {
            name: def.name.clone(),
            cim_type: cim_type_name(def.cim_type),
            state,
            value,
        });
    }
    Ok((props, notes))
}

/// The class default for a property, read from the definition that declares
/// it (walking up the chain), or an explanation of why it could not be.
fn class_default_value(
    def: &PropDef,
    leaf: &ClassLayout,
    layouts: &BTreeMap<String, Vec<ClassLayout>>,
    notes: &mut Vec<String>,
) -> PropValue {
    let mut current: Option<&ClassLayout> = Some(leaf);
    let mut depth = 0;
    while let Some(cls) = current {
        if cls.own.iter().any(|p| p.index == def.index) {
            let total = cls
                .own
                .iter()
                .map(|p| usize::from(p.index) + 1)
                .max()
                .unwrap_or(0);
            let state_bytes = (2 * total).div_ceil(8);
            if cls.default_values.len() < state_bytes {
                break;
            }
            let bits = &cls.default_values[..state_bytes];
            let values = &cls.default_values[state_bytes..];
            let i = usize::from(def.index);
            let null = (bits.get((2 * i) / 8).copied().unwrap_or(0) >> ((2 * i) % 8)) & 1 == 1;
            if null {
                return PropValue::Null;
            }
            return read_value(def, values, &cls.heap, notes);
        }
        if cls.superclass.is_empty() {
            break;
        }
        depth += 1;
        if depth > MAX_INHERITANCE_DEPTH {
            break;
        }
        current = layouts
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&cls.superclass))
            .and_then(|(_, v)| v.first());
    }
    PropValue::Undecoded(
        "the instance defers to the class default, and the defining class's default block \
         could not be read"
            .to_string(),
    )
}

/// Read one property's stored value from a value area and its heap.
fn read_value(def: &PropDef, values: &[u8], heap: &[u8], notes: &mut Vec<String>) -> PropValue {
    let off = def.offset as usize;
    let Some(width) = cim_value_size(def.cim_type) else {
        return PropValue::Undecoded(format!("CIM type {:#x} not known", def.cim_type));
    };
    let Some(raw) = values.get(off..off + width) else {
        return PropValue::Undecoded("value slot lies outside the value area".to_string());
    };
    let heap_off = || le_u32(raw, 0).map(|v| v as usize).unwrap_or(0);
    if def.cim_type & 0x2000 != 0 {
        return read_array(def.cim_type & 0xfff, heap, heap_off(), notes);
    }
    match def.cim_type & 0xfff {
        8 | 101 | 102 => match heap_string(heap, heap_off()) {
            Some((s, latin1)) => {
                if latin1 {
                    notes.push(format!(
                        "{}: bytes above 0x7f in an 8-bit string were decoded as Latin-1; the \
                         corpus held only ASCII, so the code page is not established.",
                        def.name
                    ));
                }
                PropValue::Str(s)
            }
            None => PropValue::Undecoded("string offset does not point into the heap".to_string()),
        },
        11 => PropValue::Bool(le_u16(raw, 0).unwrap_or(0) != 0),
        2 => PropValue::Signed(i64::from(i16::from_le_bytes([raw[0], raw[1]]))),
        3 => PropValue::Signed(i64::from(i32::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3],
        ]))),
        16 => PropValue::Signed(i64::from(raw[0] as i8)),
        20 => PropValue::Signed(i64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ])),
        17 => PropValue::Unsigned(u64::from(raw[0])),
        18 | 103 => PropValue::Unsigned(u64::from(le_u16(raw, 0).unwrap_or(0))),
        19 => PropValue::Unsigned(u64::from(le_u32(raw, 0).unwrap_or(0))),
        21 => PropValue::Unsigned(le_u64(raw, 0).unwrap_or(0)),
        4 => PropValue::Real(f64::from(f32::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3],
        ]))),
        5 => PropValue::Real(f64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ])),
        13 => {
            PropValue::Undecoded("embedded object values are not decoded by this build".to_string())
        }
        _ => PropValue::Undecoded(format!("CIM type {:#x} not decoded", def.cim_type)),
    }
}

/// An array value: a count in the heap followed by the elements.
fn read_array(base_type: u32, heap: &[u8], at: usize, notes: &mut Vec<String>) -> PropValue {
    let Some(count) = le_u32(heap, at).map(|c| c as usize) else {
        return PropValue::Undecoded("array offset does not point into the heap".to_string());
    };
    match base_type {
        17 | 16 => match heap.get(at + 4..at + 4 + count) {
            Some(b) => PropValue::Bytes(b.to_vec()),
            None => PropValue::Undecoded(format!(
                "byte array declares {count} elements past the end of the heap"
            )),
        },
        8 | 101 | 102 => {
            let mut out = Vec::with_capacity(count.min(1024));
            for k in 0..count.min(1024) {
                let Some(el) = le_u32(heap, at + 4 + 4 * k).map(|v| v as usize) else {
                    return PropValue::Undecoded(format!(
                        "string array declares {count} elements past the end of the heap"
                    ));
                };
                match heap_string(heap, el) {
                    Some((s, _)) => out.push(s),
                    None => {
                        return PropValue::Undecoded(format!(
                            "string array element {k} does not point into the heap"
                        ))
                    }
                }
            }
            notes.push(
                "A string array was read as a count followed by heap offsets, a layout the \
                 validation corpus shows only in class default blocks, never in an \
                 instance's own values."
                    .to_string(),
            );
            if count > 1024 {
                notes.push(format!(
                    "String array truncated to 1024 of {count} elements."
                ));
            }
            PropValue::StrArray(out)
        }
        other => PropValue::Undecoded(format!(
            "arrays of CIM type {other:#x} are not decoded by this build"
        )),
    }
}

/// A string at a heap offset: one type byte, then the text. Type 0 is 8-bit
/// (only ASCII was observed); type 1 is UTF-16LE per the documentation.
/// Returns the string and whether Latin-1 was assumed for bytes above 0x7f.
fn heap_string(heap: &[u8], at: usize) -> Option<(String, bool)> {
    let kind = *heap.get(at)?;
    let body = heap.get(at + 1..)?;
    match kind {
        0 => {
            let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
            let bytes = &body[..end.min(MAX_STRING_BYTES)];
            let latin1 = bytes.iter().any(|&b| b >= 0x80);
            Some((bytes.iter().map(|&b| b as char).collect(), latin1))
        }
        1 => {
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|&u| u != 0)
                .take(MAX_STRING_BYTES / 2)
                .collect();
            Some((String::from_utf16_lossy(&units), false))
        }
        _ => None,
    }
}

/// Printable ASCII runs of four or more characters, in order.
fn printable_runs(bytes: &[u8]) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut run = String::new();
    let mut truncated = false;
    let flush = |run: &mut String, out: &mut Vec<String>, truncated: &mut bool| {
        if run.len() >= 4 {
            if out.len() < MAX_DATA_STRINGS {
                out.push(std::mem::take(run));
            } else {
                *truncated = true;
            }
        }
        run.clear();
    };
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            if run.len() < MAX_STRING_BYTES {
                run.push(b as char);
            }
        } else {
            flush(&mut run, &mut out, &mut truncated);
        }
    }
    flush(&mut run, &mut out, &mut truncated);
    (out, truncated)
}

/// Parse a class definition record, if the bytes are one.
///
/// Layout (as read off both fixture files): a u32 character count and the
/// UTF-16LE superclass name; a FILETIME; then a block of its own size holding
/// one unknown byte, the class-name heap offset, the default-value block's
/// size, a sized superclass-name block, a sized qualifier block, the property
/// count and `count` pairs of (name offset, definition offset), the default
/// values, and a heap whose length carries a marker bit. Each property
/// definition in the heap is (u32 type, u16 index, u32 offset, u32 level,
/// sized qualifier block).
pub fn parse_class_definition(bytes: &[u8], file_offset: usize) -> Option<ClassLayout> {
    let sup_chars = le_u32(bytes, 0)? as usize;
    if sup_chars > 256 {
        return None;
    }
    let sup_end = 4 + 2 * sup_chars;
    let sup_units: Vec<u16> = bytes
        .get(4..sup_end)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let superclass = String::from_utf16(&sup_units).ok()?;
    if !superclass
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let block_at = sup_end + 8;
    let block_size = le_u32(bytes, block_at)? as usize;
    if block_size < 40 {
        return None;
    }
    let block = bytes.get(block_at..block_at + block_size)?;
    let class_name_off = le_u32(block, 5)? as usize;
    let dv_size = le_u32(block, 9)? as usize;
    let mut q = 13usize;
    let sup_block = le_u32(block, q)? as usize;
    if sup_block < 4 {
        return None;
    }
    q = q.checked_add(sup_block)?;
    let qual_block = le_u32(block, q)? as usize;
    if qual_block < 4 {
        return None;
    }
    q = q.checked_add(qual_block)?;
    let count = le_u32(block, q)? as usize;
    if count > 1024 {
        return None;
    }
    q += 4;
    let pairs_end = q.checked_add(8 * count)?;
    let dv_end = pairs_end.checked_add(dv_size)?;
    let heap_len_raw = le_u32(block, dv_end)?;
    if heap_len_raw & 0x8000_0000 == 0 {
        return None;
    }
    let heap_len = (heap_len_raw & 0x7fff_ffff) as usize;
    let heap = block.get(dv_end + 4..dv_end + 4 + heap_len)?;
    let (name, _) = heap_string(heap, class_name_off)?;
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let mut own = Vec::with_capacity(count);
    for k in 0..count {
        let name_off = le_u32(block, q + 8 * k)? as usize;
        let def_off = le_u32(block, q + 8 * k + 4)? as usize;
        let (pname, _) = heap_string(heap, name_off)?;
        if pname.is_empty() || !pname.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        let cim_type = le_u32(heap, def_off)?;
        let index = le_u16(heap, def_off + 4)?;
        let offset = le_u32(heap, def_off + 6)?;
        own.push(PropDef {
            name: pname,
            cim_type,
            index,
            offset,
        });
    }
    own.sort_by_key(|p| p.index);
    Some(ClassLayout {
        name,
        superclass,
        offset: file_offset,
        own,
        default_values: block.get(pairs_end..dv_end)?.to_vec(),
        heap: heap.to_vec(),
    })
}

/// A WMI object path as a binding stores it:
/// `[\\server\namespace:]Class.Key="value"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPathRef {
    pub namespace: Option<String>,
    pub class: String,
    pub key: Option<String>,
    pub value: Option<String>,
}

/// Split an object path into its parts. Returns `None` when no class name can
/// be read from it.
pub fn parse_object_path(path: &str) -> Option<ObjectPathRef> {
    let (namespace, rest) = if path.starts_with("\\\\") {
        match path.find(':') {
            Some(colon) => (Some(path[..colon].to_string()), &path[colon + 1..]),
            None => (None, path),
        }
    } else {
        (None, path)
    };
    let (class, keyed) = match rest.find('.') {
        Some(dot) => (&rest[..dot], Some(&rest[dot + 1..])),
        None => (rest, None),
    };
    let class = class.trim();
    if class.is_empty() || !class.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let (key, value) = match keyed.and_then(|k| k.find('=').map(|eq| (k, eq))) {
        Some((k, eq)) => {
            let key = k[..eq].trim().to_string();
            let raw = k[eq + 1..].trim();
            let value = raw
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .map(|v| v.replace("\\\"", "\""))
                .unwrap_or_else(|| raw.to_string());
            (Some(key), Some(value))
        }
        None => (None, None),
    };
    Some(ObjectPathRef {
        namespace,
        class: class.to_string(),
        key,
        value,
    })
}

/// What a consumer does when its binding fires, in one sentence, plus the
/// image and command it would run when it runs one.
#[derive(Debug, Clone, Default)]
pub struct ConsumerAction {
    pub statement: String,
    pub image: Option<String>,
    pub command: Option<String>,
    pub arguments: Option<String>,
    pub working_dir: Option<String>,
    pub split_basis: Option<crate::normalize::SplitBasis>,
    /// The extension rule a bare program name is searched under: the
    /// `CreateProcess` rule for a `CommandLineEventConsumer`, whose properties
    /// are `CreateProcess` parameters (`HUNT-244`), the default otherwise.
    pub search_rule: crate::normalize::SearchRule,
    /// True for a class this build knows how to describe.
    pub described: bool,
}

/// Describe a decoded consumer record.
pub fn consumer_action(rec: &WmiRecord) -> ConsumerAction {
    let mut action = ConsumerAction::default();
    let class = rec.class_name.as_str();
    if class.eq_ignore_ascii_case("CommandLineEventConsumer") {
        let template = rec.text("CommandLineTemplate");
        let exe = rec.text("ExecutablePath");
        action.working_dir = rec.text("WorkingDirectory").map(str::to_string);
        action.search_rule = crate::normalize::SearchRule::CreateProcessExeOnly;
        action.command = template.map(str::to_string);
        match (exe, template) {
            (Some(exe), Some(t)) => {
                action.image = Some(exe.to_string());
                action.arguments = Some(t.to_string());
                action.statement = format!(
                    "starts the process {exe} with the command line {t:?} (CommandLineEventConsumer)"
                );
            }
            (Some(exe), None) => {
                action.image = Some(exe.to_string());
                action.statement = format!("starts the process {exe} (CommandLineEventConsumer)");
            }
            (None, Some(t)) => {
                if let Some(split) = split_command(t) {
                    action.image = Some(split.image);
                    action.arguments = split.arguments;
                    action.split_basis = Some(split.basis);
                }
                action.statement =
                    format!("runs the command line {t:?} (CommandLineEventConsumer)");
            }
            (None, None) => {
                action.statement = "is a CommandLineEventConsumer whose ExecutablePath and \
                                    CommandLineTemplate are both unset in the record"
                    .to_string();
            }
        }
        action.described = true;
    } else if class.eq_ignore_ascii_case("ActiveScriptEventConsumer") {
        let engine = rec.text("ScriptingEngine").unwrap_or("an unnamed engine");
        let text = rec.text("ScriptText");
        let file = rec.text("ScriptFilename");
        action.statement = match (text, file) {
            (Some(t), _) => format!(
                "runs a {engine} script of {} characters held in the record's ScriptText \
                 (ActiveScriptEventConsumer)",
                t.chars().count()
            ),
            (None, Some(f)) => {
                action.image = Some(f.to_string());
                format!("runs the {engine} script file {f} (ActiveScriptEventConsumer)")
            }
            (None, None) => format!(
                "is an ActiveScriptEventConsumer for {engine} with neither ScriptText nor \
                 ScriptFilename set in the record"
            ),
        };
        action.described = true;
    } else if class.eq_ignore_ascii_case("NTEventLogEventConsumer") {
        action.statement = format!(
            "writes an entry to the Windows event log with source {:?} (NTEventLogEventConsumer); \
             it executes nothing",
            rec.text("SourceName").unwrap_or("")
        );
        action.described = true;
    } else if class.eq_ignore_ascii_case("LogFileEventConsumer") {
        action.statement = format!(
            "appends text to the file {:?} (LogFileEventConsumer); it executes nothing",
            rec.text("Filename").unwrap_or("")
        );
        action.described = true;
    } else if class.eq_ignore_ascii_case("SMTPEventConsumer") {
        action.statement = format!(
            "sends mail to {:?} via {:?} (SMTPEventConsumer); it executes nothing",
            rec.text("ToLine").unwrap_or(""),
            rec.text("SMTPServer").unwrap_or("")
        );
        action.described = true;
    } else {
        action.statement = format!(
            "is a consumer of class {class}, whose action this build does not describe; its \
             decoded properties are on the record"
        );
    }
    action
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn the_class_hash_is_sha256_of_the_uppercased_utf16_name_as_uppercase_hex() {
        // Read off the Lone Wolf record at 0x11f0b5.
        let sig = class_signature("__EventFilter", HashForm::Sha256);
        let text: String = sig
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| char::from(c[0]))
            .collect();
        assert_eq!(
            text,
            "47C79E62C2227EDD0FF29BF44D87F2FAF9FEDF60A18D9F82597602BD95E20BD3"
        );
        // And MD5 for XP, read off the CFReDS record at 0x74c59.
        let sig = class_signature("__EventFilter", HashForm::Md5);
        let text: String = sig
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| char::from(c[0]))
            .collect();
        assert_eq!(text, "D4A52B2BD3BF3604AD338F63412AEB3C");
    }

    #[test]
    fn an_object_path_splits_into_namespace_class_key_and_value() {
        let r = parse_object_path(
            "\\\\.\\root\\subscription:MSFT_UCScenarioControl.Name=\"Microsoft WMI Updating Consumer Scenario Control\"",
        )
        .unwrap();
        assert_eq!(r.namespace.as_deref(), Some("\\\\.\\root\\subscription"));
        assert_eq!(r.class, "MSFT_UCScenarioControl");
        assert_eq!(r.key.as_deref(), Some("Name"));
        assert_eq!(
            r.value.as_deref(),
            Some("Microsoft WMI Updating Consumer Scenario Control")
        );
        let r = parse_object_path("__EventFilter.Name=\"SCM Event Log Filter\"").unwrap();
        assert_eq!(r.namespace, None);
        assert_eq!(r.class, "__EventFilter");
        assert_eq!(r.value.as_deref(), Some("SCM Event Log Filter"));
        assert!(parse_object_path("").is_none());
        assert!(parse_object_path("not a path!").is_none());
    }

    /// The number the [`ChecksumStatus::NotStored`] rustdoc quotes, counted
    /// with the scanner's own descriptor walk over the complete Lone Wolf
    /// Windows 10 OBJECTS.DATA (23,986,176 bytes) named by
    /// `SEANCE_LONEWOLF_OBJECTS_DATA`; when the variable is unset the test
    /// says so and does not run.
    #[test]
    fn the_lonewolf_descriptor_checksum_field_census_is_what_the_rustdoc_says() {
        let Ok(path) = std::env::var("SEANCE_LONEWOLF_OBJECTS_DATA") else {
            eprintln!("SEANCE_LONEWOLF_OBJECTS_DATA unset; the checksum-field census did not run");
            return;
        };
        let buf = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let descriptors: Vec<Descriptor> = (0..buf.len() / PAGE_SIZE)
            .flat_map(|page| descriptor_table(&buf, page))
            .collect();
        let zero = descriptors.iter().filter(|d| d.checksum == 0).count();
        let non_zero_in_page = descriptors
            .iter()
            .filter(|d| d.checksum != 0 && !d.spans_pages)
            .count();
        let non_zero_spanning = descriptors
            .iter()
            .filter(|d| d.checksum != 0 && d.spans_pages)
            .count();
        assert_eq!(descriptors.len(), 11548);
        assert_eq!(
            (zero, non_zero_in_page, non_zero_spanning),
            (11470, 25, 53),
            "descriptors with a zero checksum field; non-zero within a page; non-zero spanning pages"
        );
        // None of the 78 is a record the scanner decodes: the three decoded
        // subscription records all read zero.
        let out = scan(&buf);
        assert_eq!(out.records.len(), 3);
        assert!(out
            .records
            .iter()
            .all(|r| r.checksum == ChecksumStatus::NotStored));
    }
}
