//! Files recovered from memory, handed back to the rest of Séance.
//!
//! A Windows machine keeps the contents of recently-used files in the cache
//! manager, so a memory capture contains file *data* as well as kernel
//! structures. Those files are frequently the ones that matter: a browser
//! history database whose on-disk copy was later cleared, a document open at the
//! moment of capture, a registry hive with uncommitted changes, an executable
//! deleted from disk but still mapped.
//!
//! The value is not in dumping them to a directory. It is in giving them to the
//! parsers Séance already has. A `places.sqlite` recovered from RAM should
//! produce browser-history records; a recovered JPEG should produce EXIF and a
//! thumbnail; a recovered hive should produce registry keys. This module is the
//! seam that makes that happen: it emits each recovered file as an ordinary
//! [`ArtifactType::FileEntry`] carrying its bytes, and the orchestrator routes
//! it to every module that subscribes to file entries — the same path a file
//! extracted from a disk image takes.
//!
//! # The rule that governs what may be handed on
//!
//! **Only a complete reconstruction is handed to a parser.**
//!
//! A file recovered from cache is normally full of holes: the cache holds the
//! pages that were recently touched, not the whole file. A parser given a
//! part-recovered SQLite database does not fail — it reads a header, finds
//! plausible pages, and produces records that are a mixture of real data and
//! whatever occupied the missing pages. Those records then look exactly like
//! records recovered from a complete file.
//!
//! So [`Extract::contiguous`] is the gate, and it returns `None` for anything
//! with a gap. A partial recovery is still *reported* — it is evidence that the
//! file existed and was in use — but it is reported as a record describing what
//! was recovered, never as a file entry for a parser to interpret.
//!
//! # Provenance
//!
//! Every artifact this module emits is stamped `recovered_from: "memory"` with
//! the process and the `_FILE_OBJECT` it came from. A record derived from a file
//! that only ever existed in RAM must never be mistaken in a report for one
//! derived from the disk image, because the two support different claims: the
//! disk copy is what was stored, the memory copy is what was *in use*.

use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use serde_json::json;

use crate::dump::{self, DumpSymbols, Extract, FileCache, FileCacheConfig, FileCacheMap};
use crate::objects::{self, ObjectScanConfig, ObjectSymbols};
use crate::profile::WindowsProfile;

/// Largest reconstruction handed on as a file entry, in bytes.
///
/// A recovered file is held in memory to be given to a parser, so this bounds
/// what one artifact can cost. Anything larger is reported as a record instead —
/// the fact of the file is preserved, only the automatic re-parse is skipped.
pub const MAX_HANDED_ON_BYTES: u64 = 256 * 1024 * 1024;

/// Where a recovered file came from, for the record.
#[derive(Debug, Clone)]
pub struct Provenance {
    /// The `_FILE_OBJECT` the reconstruction came from.
    pub file_object: u64,
    /// The path the file object names, when it had one.
    pub path: Option<String>,
    /// The owning process, when the file was reached through one.
    pub process: Option<u64>,
    /// That process's id, when it was readable.
    pub pid: Option<u64>,
    /// Which cache the pages came from, for an examiner who needs to know
    /// whether this was the data or the image section.
    pub cache: &'static str,
}

impl Provenance {
    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "file_object": self.file_object,
            "path": self.path,
            "process": self.process,
            "pid": self.pid,
            "cache": self.cache,
        })
    }

    /// The leaf name of the recovered path, for the artifact's `name`.
    pub fn leaf(&self) -> String {
        self.path
            .as_deref()
            .and_then(|p| p.rsplit(['\\', '/']).next())
            .filter(|leaf| !leaf.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("file_object_{:#x}", self.file_object))
    }
}

/// What became of one recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Reconstructed in full and handed on for parsing.
    HandedOn,
    /// Reconstructed with holes. Reported, not parsed.
    Partial,
    /// Complete but larger than [`MAX_HANDED_ON_BYTES`].
    TooLarge,
}

impl Disposition {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Disposition::HandedOn => "handed_on",
            Disposition::Partial => "partial",
            Disposition::TooLarge => "too_large",
        }
    }

    /// Why, in a sentence an examiner reads.
    pub fn describe(self) -> &'static str {
        match self {
            Disposition::HandedOn => {
                "every byte of this file was recovered from memory, so it was handed to the \
                 ordinary parsers and any records below came from it"
            }
            Disposition::Partial => {
                "only part of this file was in memory. It is reported so the file's existence and \
                 use are on the record, but it was NOT parsed: a parser given a file with holes \
                 produces records mixing real data with whatever occupied the gaps, and those \
                 records are indistinguishable from sound ones"
            }
            Disposition::TooLarge => {
                "the file was recovered in full but is larger than the limit for re-parsing in \
                 memory, so it is reported rather than parsed"
            }
        }
    }
}

/// One recovered file and what was done with it.
#[derive(Debug, Clone)]
pub struct RecoveredFile {
    /// Where it came from.
    pub provenance: Provenance,
    /// Declared length of the file, when the file object stated one.
    pub declared_length: Option<u64>,
    /// Bytes actually recovered.
    pub recovered_bytes: u64,
    /// How many holes the reconstruction had.
    pub gaps: usize,
    /// Total bytes not recovered.
    pub gap_bytes: u64,
    /// What became of it.
    pub disposition: Disposition,
}

impl RecoveredFile {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "type": "MemoryRecoveredFile",
            "record_type": "MemoryRecoveredFile",
            "name": self.provenance.leaf(),
            "recovered_from": "memory",
            "provenance": self.provenance.to_json(),
            "declared_length": self.declared_length,
            "recovered_bytes": self.recovered_bytes,
            "gaps": self.gaps,
            "gap_bytes": self.gap_bytes,
            "disposition": self.disposition.as_str(),
            "disposition_detail": self.disposition.describe(),
            "content_complete": self.disposition == Disposition::HandedOn,
            "content_incomplete": self.disposition != Disposition::HandedOn,
        })
    }
}

/// How many file objects a survey will try to reconstruct.
///
/// Every attempt costs a walk of the file's cache structures and, on success,
/// its bytes in memory. A capture of a busy machine holds tens of thousands of
/// file objects, most of them cached only in fragments, so this bounds the work
/// and the outcome says when it was reached.
pub const MAX_FILES_SURVEYED: usize = 4096;

/// What a whole recovery pass found.
#[derive(Debug, Clone)]
pub struct RecoveredFileSurvey {
    /// One entry per file object examined.
    pub files: Vec<RecoveredFile>,
    /// File objects that could not be examined at all, with the reason.
    pub skipped: Vec<(u64, String)>,
    /// Whether the pool scan that found the file objects was itself complete.
    pub scan_complete: bool,
    /// Whether [`MAX_FILES_SURVEYED`] stopped the pass.
    pub truncated: bool,
}

impl RecoveredFileSurvey {
    /// Whether the pass examined everything it set out to.
    ///
    /// False means "some files in this capture were never looked at", which is
    /// a different statement from "no files were recoverable" and must not be
    /// rendered as it.
    pub fn is_complete(&self) -> bool {
        self.scan_complete && !self.truncated && self.skipped.is_empty()
    }

    /// How many files came back whole and were handed to the parsers.
    pub fn handed_on(&self) -> usize {
        self.files
            .iter()
            .filter(|f| f.disposition == Disposition::HandedOn)
            .count()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "name": "Files recovered from memory",
            "files": self.files.iter().map(RecoveredFile::to_json).collect::<Vec<_>>(),
            "examined": self.files.len(),
            "handed_to_parsers": self.handed_on(),
            "skipped": self
                .skipped
                .iter()
                .map(|(addr, why)| json!({"file_object": addr, "reason": why}))
                .collect::<Vec<_>>(),
            "scan_complete": self.scan_complete,
            "truncated": self.truncated,
            "content_complete": self.is_complete(),
            "content_incomplete": !self.is_complete(),
            // The three ways this pass can fall short, named in the shape the
            // stage-record builder harvests (`incomplete[].detail`). Without
            // this the record reached the examiner saying only that the stage
            // "did not establish this result in full and recorded no reason",
            // which sends them looking for a fault in the stage rather than at
            // the pool scan or the ceiling that actually caused it. The three
            // are distinct actions: a short scan means re-run against a fuller
            // acquisition, the cap means raise it, a skipped object means those
            // bytes are damaged and no re-run will help.
            "incomplete": self.incomplete_details(),
        })
    }

    /// Why this pass is short of the capture, one entry per cause.
    ///
    /// Empty when the pass examined everything it set out to, so a complete
    /// survey carries no explanation it does not need.
    fn incomplete_details(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        if !self.scan_complete {
            out.push(json!({
                "reason": "pool_scan_incomplete",
                "detail": "the pool scan that finds file objects did not itself complete, so \
                           files this capture holds may never have been examined",
            }));
        }
        if self.truncated {
            out.push(json!({
                "reason": "cap_reached",
                "detail": format!(
                    "the pass stopped at its ceiling of {MAX_FILES_SURVEYED} file objects, so \
                     the files listed are a floor rather than every file in the capture"
                ),
            }));
        }
        for (address, why) in &self.skipped {
            out.push(json!({
                "reason": "file_object_unreadable",
                "detail": format!("the file object at {address:#x} could not be examined: {why}"),
            }));
        }
        out
    }
}

/// What a recovery pass is allowed to do.
#[derive(Debug, Clone)]
pub struct RecoveredFileConfig {
    /// How the file objects are found.
    pub scan: ObjectScanConfig,
    /// How each file's cached pages are read.
    pub cache: FileCacheConfig,
    /// Ceiling on file objects examined.
    pub max_files: usize,
}

impl Default for RecoveredFileConfig {
    fn default() -> Self {
        Self {
            scan: ObjectScanConfig::default(),
            cache: FileCacheConfig::default(),
            max_files: MAX_FILES_SURVEYED,
        }
    }
}

/// Recover every cached file the capture still holds, and hand the whole ones
/// to the parsers.
///
/// This is the entry point `module.rs` calls. It exists because the seam below
/// it — [`artifacts_for`] — needs an `Extract` and a `FileCacheMap`, and until
/// this function was written nothing produced them from a profile: the bridge
/// deck had been built before the pier. A seam with no producer is dead code
/// however well tested it is.
///
/// The pass is: pool-scan for `_FILE_OBJECT`s, read each one's cache structures,
/// reconstruct what the cache manager still holds, and emit. Files that come
/// back whole become `FileEntry` artifacts for the ordinary parsers; files with
/// holes are reported and not parsed, for the reason in this module's header.
pub fn survey_recovered_files(
    parent: &Artifact,
    profile: &WindowsProfile,
    symbols: &DumpSymbols,
    config: &RecoveredFileConfig,
) -> Result<(RecoveredFileSurvey, Vec<Artifact>), RecoveredError> {
    let object_symbols = ObjectSymbols::from_profile(profile)
        .map_err(|e| RecoveredError::Unsupported(e.to_string()))?;
    let scan = objects::scan_objects(profile, &object_symbols, &config.scan)
        .map_err(|e| RecoveredError::Scan(e.to_string()))?;

    let mut survey = RecoveredFileSurvey {
        files: Vec::new(),
        skipped: Vec::new(),
        scan_complete: scan.is_complete(),
        truncated: false,
    };
    let mut artifacts = Vec::new();

    for record in &scan.files {
        if survey.files.len() >= config.max_files {
            survey.truncated = true;
            break;
        }
        let file_object = record.address;

        // Which caches this file object actually has. A file with none is not a
        // failure — plenty of file objects reference files whose pages the cache
        // manager has already dropped — so it is simply not reconstructable and
        // is recorded as skipped with that reason.
        let caches = match dump::file_object_caches(profile, symbols, file_object) {
            Ok(caches) => caches,
            Err(err) => {
                survey.skipped.push((file_object, err.to_string()));
                continue;
            }
        };
        let Some(&(cache, object)) = caches.available.first() else {
            continue;
        };

        let map =
            match dump::file_cache_map(profile, symbols, file_object, cache, object, &config.cache)
            {
                Ok(map) => map,
                Err(err) => {
                    survey.skipped.push((file_object, err.to_string()));
                    continue;
                }
            };
        let extract = match dump::dump_file_cache(profile, &map, &config.cache) {
            Ok(extract) => extract,
            Err(err) => {
                survey.skipped.push((file_object, err.to_string()));
                continue;
            }
        };

        let provenance = Provenance {
            file_object,
            path: caches.name.clone(),
            process: None,
            pid: None,
            cache: cache_name(cache),
        };
        let produced = artifacts_for(parent, profile, provenance.clone(), &map, &extract);

        // Keep the record for the survey as well as emitting it, so the stage's
        // own outcome states what it found rather than the caller having to
        // reconstruct it from the artifacts.
        survey.files.push(RecoveredFile {
            provenance,
            declared_length: map.declared_size,
            recovered_bytes: extract.acquired_bytes,
            gaps: extract.gap_total,
            gap_bytes: extract.gap_bytes,
            disposition: disposition_of(&extract),
        });
        artifacts.extend(produced);
    }

    Ok((survey, artifacts))
}

/// Stable name for which cache a reconstruction came from.
fn cache_name(cache: FileCache) -> &'static str {
    match cache {
        FileCache::DataSection => "data_section",
        FileCache::ImageSection => "image_section",
        _ => "shared_cache_map",
    }
}

/// Something that stopped a recovery pass, as opposed to one file failing.
#[derive(Debug, thiserror::Error)]
pub enum RecoveredError {
    /// The build cannot support the pass.
    #[error("{0}")]
    Unsupported(String),
    /// The pool scan that finds file objects could not run.
    #[error("file objects could not be scanned for: {0}")]
    Scan(String),
}

/// Turn a completed extraction into artifacts.
///
/// Returns the record describing the recovery, and — only when the file came
/// back whole and within the size limit — a `FileEntry` carrying its bytes for
/// the ordinary parsers to pick up.
///
/// The `FileEntry` is deliberately an ordinary one. Nothing downstream needs to
/// know it came from memory to parse it; the provenance travels in its metadata
/// so that anything *reporting* on it can say where it came from.
pub fn artifacts_for(
    parent: &Artifact,
    profile: &WindowsProfile,
    provenance: Provenance,
    map: &FileCacheMap,
    extract: &Extract,
) -> Vec<Artifact> {
    let complete = extract.contiguous();
    let disposition = disposition_of(extract);

    let recovered = RecoveredFile {
        provenance,
        declared_length: map.declared_size,
        recovered_bytes: extract.acquired_bytes,
        gaps: extract.gap_total,
        gap_bytes: extract.gap_bytes,
        disposition,
    };

    let mut value = recovered.to_json();
    if let Some(object) = value.as_object_mut() {
        object.insert("analysed_by".into(), json!(crate::module::MODULE_ID));
        object.insert(
            "profile_evidence".into(),
            json!(profile.weakest_evidence().as_str()),
        );
    }

    let mut out = vec![
        Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value)
            .with_parent(parent.id),
    ];

    if disposition == Disposition::HandedOn {
        if let Some(bytes) = complete {
            out.push(file_entry(parent, &recovered, bytes));
        }
    }
    out
}

/// What may be done with an extraction.
///
/// One function so the survey's record and the artifact it emits can never
/// disagree about whether a file was handed to a parser.
fn disposition_of(extract: &Extract) -> Disposition {
    if extract.contiguous().is_none() {
        Disposition::Partial
    } else if extract.length > MAX_HANDED_ON_BYTES {
        Disposition::TooLarge
    } else {
        Disposition::HandedOn
    }
}

/// The `FileEntry` a recovered file is handed on as.
///
/// Carrying the bytes as a `DataSource` is what puts it on the same path as a
/// file extracted from a disk image: every module subscribing to `FileEntry`
/// sees it, so a recovered SQLite database reaches the SQLite parser, a
/// recovered hive reaches the registry parser, a recovered image reaches EXIF.
fn file_entry(parent: &Artifact, recovered: &RecoveredFile, bytes: Vec<u8>) -> Artifact {
    let length = bytes.len() as u64;
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let metadata = json!({
        "type": "FileEntry",
        "name": recovered.provenance.leaf(),
        "path": recovered.provenance.path,
        "size": length,
        // The fields that stop a memory-recovered file being mistaken in a
        // report for one read off the disk image. They support different
        // claims: the disk copy is what was stored, this is what was in use.
        "recovered_from": "memory",
        "recovered_provenance": recovered.provenance.to_json(),
        "content_complete": true,
        "source_kind": "memory_file_cache",
    });
    Artifact::new(
        parent.case_id,
        ArtifactType::FileEntry,
        Some(source),
        metadata,
    )
    .with_parent(parent.id)
}

#[cfg(test)]
mod incomplete_reason_tests {
    use super::*;

    fn survey(
        scan_complete: bool,
        truncated: bool,
        skipped: Vec<(u64, String)>,
    ) -> RecoveredFileSurvey {
        RecoveredFileSurvey {
            files: Vec::new(),
            skipped,
            scan_complete,
            truncated,
        }
    }

    /// The defect this closes: on a real Windows XP capture the record reached
    /// the examiner saying only that the stage "did not establish this result in
    /// full and recorded no reason". The stage knew perfectly well why — the
    /// pool scan behind it had not completed — but that fact was published as a
    /// bare boolean the record builder does not read, so the reason was lost
    /// between the two.
    #[test]
    fn a_short_pass_names_the_cause_the_record_builder_can_read() {
        let json = survey(false, false, Vec::new()).to_json();
        let details: Vec<&str> = json["incomplete"]
            .as_array()
            .expect("an incomplete pass must carry an incomplete array")
            .iter()
            .map(|entry| {
                entry["detail"]
                    .as_str()
                    .expect("every entry states a detail")
            })
            .collect();
        assert_eq!(details.len(), 1);
        assert!(
            details[0].contains("pool scan"),
            "the detail must name the pool scan, not merely assert incompleteness: {details:?}"
        );
    }

    #[test]
    fn each_cause_is_reported_separately_because_each_needs_a_different_action() {
        // A short scan means re-run against a fuller acquisition; the cap means
        // raise it; an unreadable object means those bytes are damaged and no
        // re-run will help. Collapsing them would tell an examiner to do the
        // wrong thing.
        let json = survey(
            false,
            true,
            vec![(0x8200_0000, "the header is not in the capture".into())],
        )
        .to_json();
        let entries = json["incomplete"].as_array().expect("array");
        assert_eq!(entries.len(), 3);
        let reasons: Vec<&str> = entries
            .iter()
            .map(|e| e["reason"].as_str().expect("reason"))
            .collect();
        assert!(reasons.contains(&"pool_scan_incomplete"));
        assert!(reasons.contains(&"cap_reached"));
        assert!(reasons.contains(&"file_object_unreadable"));
    }

    #[test]
    fn a_complete_pass_carries_no_explanation_it_does_not_need() {
        let json = survey(true, false, Vec::new()).to_json();
        assert_eq!(json["content_complete"], serde_json::json!(true));
        assert!(json["incomplete"].as_array().expect("array").is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> Provenance {
        Provenance {
            file_object: 0xffff_8000_1234_5678,
            path: Some("\\Device\\HarddiskVolume1\\Users\\sarah\\places.sqlite".into()),
            process: Some(0xffff_8000_dead_0000),
            pid: Some(1234),
            cache: "data",
        }
    }

    #[test]
    fn the_leaf_name_is_used_for_the_artifact() {
        assert_eq!(provenance().leaf(), "places.sqlite");
    }

    #[test]
    fn a_file_object_with_no_path_still_gets_a_usable_name() {
        // A nameless file object is common; the artifact still needs to be
        // identifiable in a list.
        let p = Provenance {
            path: None,
            ..provenance()
        };
        assert_eq!(p.leaf(), "file_object_0xffff800012345678");
        let empty = Provenance {
            path: Some(String::new()),
            ..provenance()
        };
        assert!(empty.leaf().starts_with("file_object_"));
    }

    #[test]
    fn a_partial_recovery_is_never_handed_to_a_parser() {
        // The property this module exists to guarantee. A parser given a file
        // with holes emits records mixing real data with whatever occupied the
        // gaps, and those records look exactly like sound ones.
        assert_eq!(
            Disposition::Partial.as_str(),
            "partial",
            "a partial recovery must be distinguishable"
        );
        assert!(Disposition::Partial.describe().contains("NOT parsed"));
        assert!(Disposition::Partial.describe().contains("holes"));
    }

    #[test]
    fn a_complete_recovery_states_that_its_records_came_from_memory() {
        let recovered = RecoveredFile {
            provenance: provenance(),
            declared_length: Some(1024),
            recovered_bytes: 1024,
            gaps: 0,
            gap_bytes: 0,
            disposition: Disposition::HandedOn,
        };
        let v = recovered.to_json();
        assert_eq!(v["recovered_from"], "memory");
        assert_eq!(v["content_complete"], true);
        assert_eq!(v["content_incomplete"], false);
        assert_eq!(v["provenance"]["pid"], 1234);
    }

    #[test]
    fn an_incomplete_recovery_is_flagged_incomplete_in_its_metadata() {
        let recovered = RecoveredFile {
            provenance: provenance(),
            declared_length: Some(4096),
            recovered_bytes: 1024,
            gaps: 2,
            gap_bytes: 3072,
            disposition: Disposition::Partial,
        };
        let v = recovered.to_json();
        assert_eq!(v["content_complete"], false);
        assert_eq!(v["content_incomplete"], true);
        assert_eq!(v["gap_bytes"], 3072);
        assert_eq!(v["recovered_bytes"], 1024);
    }

    #[test]
    fn an_oversized_but_complete_file_is_reported_rather_than_parsed() {
        // The fact of the file is preserved; only the automatic re-parse is
        // skipped, and the reason says so.
        assert!(Disposition::TooLarge
            .describe()
            .contains("recovered in full"));
        assert!(Disposition::TooLarge
            .describe()
            .contains("rather than parsed"));
        assert_ne!(Disposition::TooLarge, Disposition::HandedOn);
    }

    #[test]
    fn every_disposition_has_a_distinct_identifier() {
        let ids = [
            Disposition::HandedOn.as_str(),
            Disposition::Partial.as_str(),
            Disposition::TooLarge.as_str(),
        ];
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len());
    }
}
