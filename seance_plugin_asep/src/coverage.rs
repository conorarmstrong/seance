//! The `AsepCoverage` record: what was looked for, where, and with what result.
//!
//! Completeness is the whole forensic value of an ASEP enumeration. An examiner
//! asks "what runs at boot on this machine" once and acts on the answer, so a
//! category that was never checked must not read the same as a category that
//! was checked and found empty, and neither must read the same as a category
//! that does not belong in the hive being examined.
//!
//! One coverage record is emitted per parsed hive. It lists **every** category
//! in [`crate::rules::CATEGORIES`] — including the ones that produced nothing
//! and the ones this build cannot read at all — with a status, a count and,
//! where the status is anything other than a clean read, the reason. A category
//! that would otherwise be invisible in a case (because no hive that could
//! carry it was ingested) is still named here, tagged with the hive it needs.
//!
//! A second kind of coverage record, built by [`build_wmi_coverage_artifact`],
//! is emitted once per `OBJECTS.DATA` file scanned. It carries the same
//! category table, with the WMI category's outcome and the scan's numbers, and
//! every registry- or filesystem-backed category marked as not applicable to
//! the repository file.

use crate::record::MODULE_ID;
use crate::rules::{applies_to_hive, CategorySource, HiveKind, CATEGORIES, MITRE_TACTIC};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

/// The result of looking for one category in one hive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStatus {
    /// The locations were read in full. `entries` may be zero, which means
    /// "checked, none present" — a positive finding, not a gap.
    Examined,
    /// The locations were read but this build can only decode part of what it
    /// found, or a cap stopped the scan.
    ExaminedPartial,
    /// This hive cannot carry the category, so its absence here says nothing
    /// about the machine. The hive that would carry it is named.
    NotApplicableToHive,
    /// The category was not read. Never conflate with `Examined` at zero.
    Unexamined,
    /// The category is enumerated from a different evidence source than this
    /// hive, and is reported per item there.
    ExaminedElsewhere,
}

impl CoverageStatus {
    /// Stable string form written into the record.
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageStatus::Examined => "examined",
            CoverageStatus::ExaminedPartial => "examined_partial",
            CoverageStatus::NotApplicableToHive => "not_applicable_to_hive",
            CoverageStatus::Unexamined => "unexamined",
            CoverageStatus::ExaminedElsewhere => "examined_from_another_source",
        }
    }
}

/// Everything the coverage record needs to know about one hive scan.
#[derive(Debug, Clone)]
pub struct HiveScanSummary {
    /// Hive name as the registry parser recorded it.
    pub hive_name: String,
    /// Classified hive.
    pub hive_kind: HiveKind,
    /// The hive file's own path on the volume, when it was seen.
    pub hive_path: Option<String>,
    /// Profile the hive belongs to, for per-user hives.
    pub user: Option<String>,
    /// Values the parsed hive record claims to hold.
    pub values_total: usize,
    /// Values this scan actually examined.
    pub values_scanned: usize,
    /// Keys the parsed hive record reported, for scale.
    pub keys_total: usize,
    /// The value scan hit its ceiling and stopped before the end of the hive.
    pub scan_capped: bool,
    /// The per-hive entry ceiling was hit and further entries were dropped.
    pub entries_capped: bool,
    /// Set when the parsed hive record did not carry a usable value array. Every
    /// registry category is then reported as unexamined rather than as empty:
    /// nothing was read, so nothing can be said about what is or is not there.
    pub values_unavailable_reason: Option<String>,
    /// Entries emitted per category id.
    pub counts: BTreeMap<&'static str, usize>,
    /// Extra per-category notes, e.g. how many in-System32 COM servers were
    /// examined and deliberately excluded from the listing.
    pub notes: BTreeMap<&'static str, String>,
    /// Hive-level notes about the scan itself — a ceiling reached outside any
    /// one category, a piece of provenance that could not be established.
    /// Rendered onto the record so a limit is never silently absorbed.
    pub scan_notes: Vec<String>,
}

impl HiveScanSummary {
    /// A summary with no findings yet.
    pub fn new(hive_name: String, hive_kind: HiveKind) -> Self {
        Self {
            hive_name,
            hive_kind,
            hive_path: None,
            user: None,
            values_total: 0,
            values_scanned: 0,
            keys_total: 0,
            scan_capped: false,
            entries_capped: false,
            values_unavailable_reason: None,
            counts: BTreeMap::new(),
            notes: BTreeMap::new(),
            scan_notes: Vec::new(),
        }
    }

    /// Record one emitted entry against its category.
    pub fn count(&mut self, category: &'static str) {
        let slot = self.counts.entry(category).or_insert(0);
        *slot = slot.saturating_add(1);
    }

    /// Attach a per-category note, appending to any note already recorded.
    ///
    /// Appending rather than replacing matters: a category can hit more than one
    /// limit in one scan, and overwriting would drop the statement of one of
    /// them, leaving a partial result described as if only one thing was missed.
    pub fn note(&mut self, category: &'static str, note: impl Into<String>) {
        let note = note.into();
        match self.notes.get_mut(category) {
            Some(existing) => {
                existing.push(' ');
                existing.push_str(&note);
            }
            None => {
                self.notes.insert(category, note);
            }
        }
    }

    /// Whether anything about this scan was incomplete.
    pub fn incomplete(&self) -> bool {
        self.scan_capped
            || self.entries_capped
            || self.values_unavailable_reason.is_some()
            || !self.scan_notes.is_empty()
            || self.values_scanned < self.values_total
    }

    /// The standard classification of [`HiveScanSummary::incomplete`].
    ///
    /// What an examiner learns: whether the coverage record is short because a
    /// parser cap stopped the scan (raising it would find more) or because the
    /// hive itself would not yield its values (nothing will). `None` when the
    /// scan was complete. Reported as `content_incomplete_reason`, the key the
    /// API and export honesty paths read — `incomplete` alone is ASEP-local and
    /// invisible to them (B3-025).
    pub fn incomplete_code(&self) -> Option<IncompleteReason> {
        if self.scan_capped || self.entries_capped {
            return Some(IncompleteReason::CapReached);
        }
        if self.values_unavailable_reason.is_some()
            || !self.scan_notes.is_empty()
            || self.values_scanned < self.values_total
        {
            return Some(IncompleteReason::UnresolvedStructure);
        }
        None
    }
}

/// Build the coverage record for one hive scan.
pub fn build_coverage_artifact(
    summary: &HiveScanSummary,
    case_id: Uuid,
    parent_id: Uuid,
    registry_record_id: Uuid,
) -> Artifact {
    let mut categories = Vec::with_capacity(CATEGORIES.len());
    let mut unexamined = Vec::new();
    let mut examined_empty = Vec::new();

    for info in CATEGORIES {
        let count = summary.counts.get(info.id).copied().unwrap_or(0);
        let mut row = Map::new();
        row.insert("category".to_string(), json!(info.id));
        row.insert("label".to_string(), json!(info.label));
        row.insert("mitre_technique".to_string(), json!(info.technique));
        row.insert("locations_checked".to_string(), json!(info.locations));
        row.insert("entries".to_string(), json!(count));

        let (status, reason): (CoverageStatus, Option<String>) = match info.source {
            CategorySource::WmiRepository => (
                CoverageStatus::ExaminedElsewhere,
                Some(
                    "Enumerated from \\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA by a \
                     record-level scan, not from this hive. The outcome is stated on the \
                     AsepCoverage record whose hive is 'OBJECTS.DATA'; if the case holds no \
                     such record, the repository file was not in the evidence and this \
                     category is unexamined, not empty."
                        .to_string(),
                ),
            ),
            CategorySource::FileSystem => (
                CoverageStatus::ExaminedElsewhere,
                Some(
                    "Enumerated from the filesystem rather than this hive. Each item found \
                     is emitted as its own entry; items that could not be decoded are \
                     emitted with read_status 'unread' rather than dropped."
                        .to_string(),
                ),
            ),
            CategorySource::Registry => {
                if let Some(reason) = summary.values_unavailable_reason.as_deref() {
                    (CoverageStatus::Unexamined, Some(reason.to_string()))
                } else if summary.hive_kind == HiveKind::Other {
                    (
                        CoverageStatus::Unexamined,
                        Some(format!(
                            "The hive '{}' is not one this build recognises as a carrier of \
                             autostart locations, so its keys were not matched against this \
                             category. Absence here is not evidence of absence on the machine.",
                            summary.hive_name
                        )),
                    )
                } else if !applies_to_hive(info, summary.hive_kind) {
                    (
                        CoverageStatus::NotApplicableToHive,
                        Some(format!(
                            "This category lives in {}. It cannot appear in a {} hive, so \
                             finding none here says nothing about the machine.",
                            hive_list(info.hives),
                            summary.hive_kind.as_str()
                        )),
                    )
                } else if summary.scan_capped || summary.entries_capped {
                    (
                        CoverageStatus::ExaminedPartial,
                        Some(format!(
                            "The scan of this hive stopped at a ceiling ({} of {} values \
                             examined{}), so this count is a lower bound.",
                            summary.values_scanned,
                            summary.values_total,
                            if summary.entries_capped {
                                "; the per-hive entry ceiling was also reached"
                            } else {
                                ""
                            }
                        )),
                    )
                } else if let Some(partial) = info.partial_reason {
                    (CoverageStatus::ExaminedPartial, Some(partial.to_string()))
                } else {
                    (CoverageStatus::Examined, None)
                }
            }
        };

        row.insert("status".to_string(), json!(status.as_str()));
        row.insert("status_reason".to_string(), json!(reason));
        if status == CoverageStatus::NotApplicableToHive {
            row.insert(
                "carried_by_hives".to_string(),
                json!(info.hives.iter().map(|h| h.as_str()).collect::<Vec<_>>()),
            );
        }
        if let Some(note) = summary.notes.get(info.id) {
            row.insert("note".to_string(), json!(note));
        }

        match status {
            CoverageStatus::Unexamined => unexamined.push(info.id),
            CoverageStatus::Examined if count == 0 => examined_empty.push(info.id),
            _ => {}
        }
        categories.push(Value::Object(row));
    }

    let total: usize = summary
        .counts
        .values()
        .fold(0usize, |acc, v| acc.saturating_add(*v));

    let mut m = Map::new();
    m.insert("type".to_string(), json!("AsepCoverage"));
    m.insert(
        "name".to_string(),
        json!(format!(
            "ASEP coverage: {} ({} entries)",
            summary.hive_name, total
        )),
    );
    m.insert("hive".to_string(), json!(summary.hive_name));
    m.insert("hive_kind".to_string(), json!(summary.hive_kind.as_str()));
    m.insert("scope".to_string(), json!(summary.hive_kind.scope()));
    m.insert("hive_path".to_string(), json!(summary.hive_path));
    m.insert("user".to_string(), json!(summary.user));
    m.insert("mitre_tactic".to_string(), json!(MITRE_TACTIC));
    m.insert("values_total".to_string(), json!(summary.values_total));
    m.insert("values_scanned".to_string(), json!(summary.values_scanned));
    m.insert("keys_total".to_string(), json!(summary.keys_total));
    m.insert("scan_notes".to_string(), json!(summary.scan_notes));
    m.insert("scan_capped".to_string(), json!(summary.scan_capped));
    m.insert("entries_capped".to_string(), json!(summary.entries_capped));
    m.insert("incomplete".to_string(), json!(summary.incomplete()));
    // The standard pair alongside the ASEP-local `incomplete`: a coverage record
    // that under-reports its own scan must be visible to the cross-plugin
    // honesty paths, which key on these names (B3-025).
    if let Some(code) = summary.incomplete_code() {
        m.insert("content_incomplete".to_string(), json!(true));
        m.insert(
            "content_incomplete_reason".to_string(),
            json!(code.as_str()),
        );
        m.insert("inventory_incomplete".to_string(), json!(true));
        m.insert(
            "inventory_incomplete_reason".to_string(),
            json!(code.as_str()),
        );
    }
    m.insert(
        "values_unavailable_reason".to_string(),
        json!(summary.values_unavailable_reason),
    );
    m.insert("entries_total".to_string(), json!(total));
    m.insert("categories".to_string(), Value::Array(categories));
    m.insert("unexamined_categories".to_string(), json!(unexamined));
    m.insert(
        "examined_and_empty_categories".to_string(),
        json!(examined_empty),
    );
    m.insert(
        "reading_note".to_string(),
        json!(
            "A category with status 'examined' and zero entries was looked for and not \
               found. A category with status 'unexamined' was NOT looked for and says \
               nothing about this machine. These are different findings and must not be \
               reported as the same."
        ),
    );
    m.insert(
        "registry_record_artifact_id".to_string(),
        json!(registry_record_id.to_string()),
    );
    m.insert("source_module".to_string(), json!(MODULE_ID));
    m.insert(
        "short_desc".to_string(),
        json!(format!(
            "ASEP coverage for {}: {} entries, {} categories unexamined",
            summary.hive_name,
            total,
            unexamined.len()
        )),
    );

    Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
        .with_parent(parent_id)
}

fn hive_list(hives: &[HiveKind]) -> String {
    if hives.is_empty() {
        return "no registry hive".to_string();
    }
    hives
        .iter()
        .map(|h| format!("the {} hive", h.as_str()))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// What one `OBJECTS.DATA` scan reports about itself.
#[derive(Debug, Clone, Copy)]
pub struct WmiCoverageInput<'a> {
    /// The repository file's path on the volume.
    pub path: &'a str,
    /// The scan, or `None` when the file was seen but its content could not
    /// be read; the WMI category is then reported as unexamined.
    pub outcome: Option<&'a crate::wmi::ScanOutcome>,
    /// Why the content was not read, when `outcome` is `None`.
    pub unread_reason: Option<&'a str>,
    /// A read ceiling or short read that bounded the scan, when one did.
    pub capped_note: Option<&'a str>,
    /// Entries emitted from the scan, decoded or unread.
    pub entries_emitted: usize,
    /// What looking beside the file for its page mapping found (HUNT-195);
    /// `None` when the content was not read, so nothing was looked for.
    pub mapping: Option<&'a crate::wmi_mapping::MappingRead>,
    pub case_id: Uuid,
    pub parent_id: Uuid,
    pub file_artifact_id: Uuid,
}

/// Build the coverage record for one `OBJECTS.DATA` scan.
pub fn build_wmi_coverage_artifact(input: WmiCoverageInput<'_>) -> Artifact {
    let WmiCoverageInput {
        path,
        outcome,
        unread_reason,
        capped_note,
        entries_emitted,
        mapping,
        case_id,
        parent_id,
        file_artifact_id,
    } = input;
    let mut categories = Vec::with_capacity(CATEGORIES.len());
    let mut unexamined = Vec::new();
    let mut examined_empty = Vec::new();

    for info in CATEGORIES {
        let mut row = Map::new();
        row.insert("category".to_string(), json!(info.id));
        row.insert("label".to_string(), json!(info.label));
        row.insert("mitre_technique".to_string(), json!(info.technique));
        row.insert("locations_checked".to_string(), json!(info.locations));

        let (status, reason, count): (CoverageStatus, Option<String>, usize) = if info.source
            == CategorySource::WmiRepository
        {
            match (outcome, unread_reason) {
                (Some(out), _) => {
                    let s = &out.summary;
                    let partial = s.capped
                        || s.records_undecodable > 0
                        || s.records_spanning_pages > 0
                        || capped_note.is_some();
                    let mut reason = info.partial_reason.unwrap_or("").to_string();
                    if let Some((file, seq)) = &out.mapping_file {
                        reason.push_str(&format!(
                                " This file was read through its page mapping, {file} \
                                 (sequence number {seq}): {} of {} spanning record(s) were \
                                 read whole through it ({} spanning record(s) could not be \
                                 followed: in unmapped pages, or running past the mapping), and {} record(s) of the subscription \
                                 classes lie in pages it maps to no logical page: a record a \
                                 descriptor table lists there is reported as a superseded \
                                 copy, one no descriptor table lists as recovered residue.{}",
                                s.descriptors_reassembled,
                                s.descriptors_spanning_pages,
                                s.descriptors_spanning_unresolved,
                                s.records_in_unmapped_pages,
                                index_sentence(out)
                            ));
                        reason.push_str(&mapping_withheld_sentence(mapping, true));
                    } else {
                        reason.push_str(&mapping_absent_sentence(mapping));
                    }
                    if let Some(note) = capped_note {
                        reason.push(' ');
                        reason.push_str(note);
                    }
                    if let Some(note) = s.cap_note.as_deref() {
                        reason.push(' ');
                        reason.push_str(note);
                    }
                    if s.records_undecodable > 0 {
                        reason.push_str(&format!(
                            " {} matched record(s) could not be decoded and are emitted \
                                 as unread entries.",
                            s.records_undecodable
                        ));
                    }
                    if s.descriptors_spanning_pages > 0 && !s.mapping_used {
                        reason.push_str(&format!(
                            " {} of the {} descriptor-listed record(s) declare a size \
                                 that runs past their page; those were not tried as class \
                                 definitions (the continuation lies in a page only the \
                                 unread mapping can name), so a class whose only definition \
                                 is such a record has no layout here and its instances are \
                                 reported undecodable for want of one.",
                            s.descriptors_spanning_pages, s.descriptor_records
                        ));
                    }
                    (
                        if partial {
                            CoverageStatus::ExaminedPartial
                        } else {
                            CoverageStatus::Examined
                        },
                        Some(reason),
                        entries_emitted,
                    )
                }
                (None, reason) => (
                    CoverageStatus::Unexamined,
                    Some(
                        reason
                            .unwrap_or("The repository file's content was not read.")
                            .to_string(),
                    ),
                    0,
                ),
            }
        } else {
            (
                CoverageStatus::NotApplicableToHive,
                Some(format!(
                    "This category lives in {}, not in the WMI repository file, so it is \
                         not examined here.",
                    match info.source {
                        CategorySource::Registry => hive_list(info.hives),
                        CategorySource::FileSystem => "the filesystem".to_string(),
                        CategorySource::WmiRepository => unreachable!(),
                    }
                )),
                0,
            )
        };

        row.insert("entries".to_string(), json!(count));
        row.insert("status".to_string(), json!(status.as_str()));
        row.insert("status_reason".to_string(), json!(reason));
        if status == CoverageStatus::NotApplicableToHive && !info.hives.is_empty() {
            row.insert(
                "carried_by_hives".to_string(),
                json!(info.hives.iter().map(|h| h.as_str()).collect::<Vec<_>>()),
            );
        }
        match status {
            CoverageStatus::Unexamined => unexamined.push(info.id),
            CoverageStatus::Examined if count == 0 => examined_empty.push(info.id),
            _ => {}
        }
        categories.push(Value::Object(row));
    }

    let incomplete_code = match outcome {
        Some(out) if out.summary.capped || capped_note.is_some() => {
            Some(IncompleteReason::CapReached)
        }
        Some(out)
            if out.summary.records_undecodable > 0 || out.summary.records_spanning_pages > 0 =>
        {
            Some(IncompleteReason::UnresolvedStructure)
        }
        Some(_) => None,
        None => Some(IncompleteReason::UnresolvedStructure),
    };

    let mut m = Map::new();
    m.insert("type".to_string(), json!("AsepCoverage"));
    m.insert(
        "name".to_string(),
        json!(format!(
            "ASEP coverage: OBJECTS.DATA ({entries_emitted} entries)"
        )),
    );
    m.insert("hive".to_string(), json!("OBJECTS.DATA"));
    m.insert("hive_kind".to_string(), json!("WMI_REPOSITORY"));
    m.insert("scope".to_string(), json!("machine"));
    m.insert("hive_path".to_string(), json!(path));
    m.insert("user".to_string(), Value::Null);
    m.insert("mitre_tactic".to_string(), json!(MITRE_TACTIC));
    m.insert("scan_notes".to_string(), json!(Vec::<String>::new()));
    m.insert("incomplete".to_string(), json!(incomplete_code.is_some()));
    if let Some(code) = incomplete_code {
        m.insert("content_incomplete".to_string(), json!(true));
        m.insert(
            "content_incomplete_reason".to_string(),
            json!(code.as_str()),
        );
        m.insert("inventory_incomplete".to_string(), json!(true));
        m.insert(
            "inventory_incomplete_reason".to_string(),
            json!(code.as_str()),
        );
    }
    if let Some(out) = outcome {
        let s = &out.summary;
        m.insert(
            "wmi_scan".to_string(),
            json!({
                "method": "record-level scan of OBJECTS.DATA pages",
                "index_walked": s.index_read,
                "mapping_read": out.mapping_file.is_some(),
                "mapping_file": out.mapping_file.as_ref().map(|(f, _)| f),
                "mapping_sequence": out.mapping_file.as_ref().map(|(_, s)| s),
                "mapping_could_look": mapping.map(|m| m.could_look),
                "mappings_older": mapping.map(|m| m.older.iter().map(|(f, s)| json!({"file": f, "sequence": s})).collect::<Vec<_>>()).unwrap_or_default(),
                "mappings_refused": mapping.map(|m| m.refused.iter().map(|(f, r)| json!({"file": f, "reason": r})).collect::<Vec<_>>()).unwrap_or_default(),
                "mappings_not_found": mapping.map(|m| m.not_found.clone()).unwrap_or_default(),
                "mappings_withheld": mapping.map(|m| m.withheld.clone()).unwrap_or_default(),
                "logical_pages": s.logical_pages,
                "pages_mapped": s.pages_mapped,
                "pages_continuation": s.pages_continuation,
                "pages_unmapped": s.pages_unmapped,
                "mapped_pages_beyond_file": s.mapped_pages_beyond_file,
                "descriptors_reassembled": s.descriptors_reassembled,
                "descriptors_spanning_unresolved": s.descriptors_spanning_unresolved,
                "descriptors_in_unmapped_pages": s.descriptors_in_unmapped_pages,
                "records_in_unmapped_pages": s.records_in_unmapped_pages,
                "bytes_scanned": s.bytes_scanned,
                "pages": s.pages,
                "trailing_bytes": s.trailing_bytes,
                "pages_with_descriptor_table": s.pages_with_descriptor_table,
                "descriptor_records": s.descriptor_records,
                "descriptors_spanning_pages": s.descriptors_spanning_pages,
                "descriptors_tried_as_class_definitions": s.descriptors_tried_as_class_definitions,
                "class_definitions_seen": s.class_definitions_seen,
                "classes_scanned": s.classes_scanned,
                "classes_added_from_bindings": s.classes_added_from_bindings,
                "classes_without_definition": s.classes_without_definition,
                "signature_hits": s.signature_hits,
                "hits_inside_other_records": s.hits_inside_other_records,
                "unreferenced_hits": s.unreferenced_hits,
                "records_matched": s.instance_records_matched,
                "records_decoded": s.records_decoded,
                "records_undecodable": s.records_undecodable,
                "records_spanning_pages": s.records_spanning_pages,
                "record_cap": crate::wmi::MAX_RECORDS,
                "capped": s.capped,
                "cap_note": s.cap_note,
            }),
        );
        // Added outside the literal above, which is at serde_json's macro
        // recursion limit.
        if let Some(Value::Object(scan)) = m.get_mut("wmi_scan") {
            scan.insert(
                "reassembled_checksums_verified".to_string(),
                json!(s.reassembled_checksums_verified),
            );
            scan.insert(
                "reassembled_checksums_mismatched".to_string(),
                json!(s.reassembled_checksums_mismatched),
            );
            scan.insert("index_read".to_string(), json!(s.index_read));
            scan.insert(
                "index_unread_reason".to_string(),
                match &out.index {
                    crate::wmi_index::IndexRead::Unread(why) => json!(why),
                    crate::wmi_index::IndexRead::Read(_) => Value::Null,
                },
            );
            scan.insert(
                "index_data_references".to_string(),
                json!(s.index_data_references),
            );
            scan.insert(
                "index_pages_visited".to_string(),
                json!(s.index_pages_visited),
            );
            scan.insert(
                "descriptors_listed_not_indexed".to_string(),
                json!(s.descriptors_listed_not_indexed),
            );
            scan.insert("records_indexed".to_string(), json!(s.records_indexed));
            scan.insert(
                "records_listed_not_indexed".to_string(),
                json!(s.records_listed_not_indexed),
            );
        }
    }
    m.insert("entries_total".to_string(), json!(entries_emitted));
    m.insert("categories".to_string(), Value::Array(categories));
    m.insert("unexamined_categories".to_string(), json!(unexamined));
    m.insert(
        "examined_and_empty_categories".to_string(),
        json!(examined_empty),
    );
    m.insert(
        "reading_note".to_string(),
        json!(
            "This record covers one WMI repository file. Only the WMI event subscription \
               category can be examined here; every other category is carried by a registry \
               hive or the filesystem and is reported on its own coverage record. A record \
               found by the scan is one that exists in the file's pages. When the page \
               mapping beside the file was read, each record says whether its page is \
               current or a superseded free page; when it was not, whether the repository \
               still mapped the record was not established. When the index (INDEX.BTR) beside \
               it was also read, each record a mapped page lists says whether the index, \
               walked from its root, names it; when it was not, the coverage record says why."
        ),
    );
    m.insert(
        "registry_record_artifact_id".to_string(),
        json!(file_artifact_id.to_string()),
    );
    m.insert("source_module".to_string(), json!(MODULE_ID));
    m.insert(
        "short_desc".to_string(),
        json!(format!(
            "ASEP coverage for OBJECTS.DATA: {entries_emitted} entries, {} categories unexamined",
            unexamined.len()
        )),
    );

    Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
        .with_parent(parent_id)
}

/// What the coverage row says of the index (HUNT-195).
fn index_sentence(out: &crate::wmi::ScanOutcome) -> String {
    match &out.index {
        crate::wmi_index::IndexRead::Read(_) => format!(
            " INDEX.BTR was read and walked from its root ({} page(s), {} data reference(s)): \
             {} descriptor-listed record(s) in mapped pages are named by no key of the index, \
             {} subscription-class record(s) are named by it and {} are listed by a mapped \
             page but not named by it.",
            out.summary.index_pages_visited,
            out.summary.index_data_references,
            out.summary.descriptors_listed_not_indexed,
            out.summary.records_indexed,
            out.summary.records_listed_not_indexed
        ),
        crate::wmi_index::IndexRead::Unread(why) => {
            format!(" INDEX.BTR was not read: {why}.")
        }
    }
}

/// The sentence a WMI coverage row carries when no page mapping was used:
/// could not look, looked and found none, or found only refused ones.
fn mapping_absent_sentence(mapping: Option<&crate::wmi_mapping::MappingRead>) -> String {
    let withheld = mapping_withheld_sentence(mapping, false);
    let base = match mapping {
        Some(m) if !m.refused.is_empty() => format!(
            " No page mapping was used: {}.",
            m.refused
                .iter()
                .map(|(f, r)| format!("{f} was refused ({r})"))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        // Every mapping file present was withheld (its name occurs more than
        // once): the source did look, and what it found it would not choose.
        Some(m) if !m.withheld.is_empty() => {
            if m.not_found.is_empty() {
                " No page mapping was used.".to_string()
            } else {
                format!(
                    " No page mapping was used ({} not found beside the file).",
                    m.not_found.join(", ")
                )
            }
        }
        Some(m) if m.could_look => format!(
            " No page mapping was found beside the file ({} looked for).",
            m.not_found.join(", ")
        ),
        _ => " The file's source could not look beside it for the page mapping, so none \
              was read."
            .to_string(),
    };
    base + &withheld
}

/// The sentence naming mapping files present beside the file but withheld
/// because the directory holds the name more than once (HUNT-195). `used`
/// is whether another mapping was used, which may then not be the newest.
fn mapping_withheld_sentence(
    mapping: Option<&crate::wmi_mapping::MappingRead>,
    used: bool,
) -> String {
    let Some(m) = mapping.filter(|m| !m.withheld.is_empty()) else {
        return String::new();
    };
    let names = m.withheld.join(", ");
    let (was, each) = if m.withheld.len() == 1 {
        ("was", "")
    } else {
        ("were", " each")
    };
    if used {
        format!(
            " {names} {was}{each} present beside the file more than once and {was} withheld, \
             not chosen between, so the mapping used may not be the newest."
        )
    } else {
        format!(
            " {names} {was}{each} present beside the file more than once and {was} withheld, \
             not chosen between."
        )
    }
}
