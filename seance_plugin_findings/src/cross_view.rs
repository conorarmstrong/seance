//! Findings that need two views of the case at once (§2.2, detections 3 and 6).
//!
//! # Why these are not modules
//!
//! Every other detection in this crate reads one record and decides. These
//! read one record and ask a question about *the rest of the case* — is there a
//! file entry for this program anywhere? does the MFT still describe the file
//! the journal says was deleted? A [`ForensicsModule`] cannot answer either.
//! It sees artifacts as they are produced, so an index built as the walk
//! proceeds would answer from whatever had been walked when the prefetch file
//! happened to be parsed, and "no file entry for this program" would be true
//! of most of a healthy system directory until the walk finished.
//!
//! A false absence is the class of defect this project treats as HIGH, and a
//! triage list full of them is the mistake `HUNT-051` recorded: a detection
//! that fires on a sixth of a clean disk teaches its reader to stop reading.
//! So these run over the completed populations, the way the Connections and
//! Duplicates views already do.
//!
//! [`ForensicsModule`]: seance_core::module::ForensicsModule
//!
//! # What is in here and what is not
//!
//! The functions in this module are pure: they take the claims extracted from
//! the execution and journal records, take the answers a name lookup gave, and
//! return findings. Fetching the populations is the caller's job (`seance_api`
//! does it against the database), which is what makes every rule here testable
//! against a table of inputs rather than against a case.
//!
//! # Which records say a program ran, and which do not
//!
//! **Only prefetch does.** A prefetch file exists because Windows prepared
//! that image for execution. The other two Windows artifacts an examiner
//! reaches for first record something weaker, and this module keeps the
//! difference:
//!
//! * **Amcache** `InventoryApplicationFile` and `File` entries record that
//!   Windows *catalogued* the file. They carry no run count and no last-run
//!   time and the reader emits none, so they raise their own two detections —
//!   `inventoried_binary_absent_from_filesystem` and
//!   `inventoried_binary_only_deleted_entries` — whose title, observation and
//!   inference say "catalogued" and never "ran". This was a shipped defect:
//!   an Amcache entry raised a finding titled "`name` ran, and no file entry
//!   for it was recovered", observed that "AmcacheEntry records that `name`
//!   was run on this machine" and inferred that the program "ran and … was
//!   removed after it ran". See [`ClaimBasis`].
//! * **The shimcache is not a source of claims at all.** An entry in the
//!   application-compatibility cache means Windows looked at the file, not
//!   that it ran it; the `exec_flag` that is sometimes read as execution is a
//!   shim-database flag whose meaning varies by Windows version, and this
//!   build reads it only on the Windows 7 and Vista layouts.
//!
//! The kind is split rather than only the words because the machine-readable
//! field has to be true too: somebody filtering a case on `execution_*` must
//! not be handed a presence record.

use crate::prelude::*;
use std::collections::HashMap;

/// The module id these findings cite. Not a registered [`ForensicsModule`] —
/// see the module documentation — but a finding still has to name the code
/// that made the claim.
///
/// [`ForensicsModule`]: seance_core::module::ForensicsModule
pub const CROSS_VIEW_MODULE_ID: &str = "findings.cross_view";

/// Every finding kind this module can raise.
///
/// These detections are not registered modules, so nothing in the module
/// registry can be compared against the API's `FINDING_DETECTIONS` list for
/// them. This constant is what stands in its place: `seance_api` asserts its
/// cross-view declarations against this list, and
/// `every_kind_this_module_raises_is_declared` asserts this list against what
/// the functions below actually produce. An undeclared detection would make an
/// empty triage list read as "nothing is wrong".
pub const CROSS_VIEW_KINDS: &[&str] = &[
    "execution_of_absent_binary",
    "execution_of_deleted_binary",
    "inventoried_binary_absent_from_filesystem",
    "inventoried_binary_only_deleted_entries",
    "usn_delete_contradicts_mft",
];

/// What the record a claim came from actually establishes.
///
/// **The distinction this type exists for is the difference between a lead and
/// a false statement.** Both of the records these rules read name a program
/// and a machine, and only one of them is about the program having run:
///
/// * a **prefetch** file exists because Windows prepared that image for
///   execution, so `Executed` is what it supports — though not by whom, and
///   not by a person rather than a service or a scheduled task;
/// * an **Amcache** `InventoryApplicationFile` or `File` entry exists because
///   Windows *catalogued* the file. It carries no run count and no last-run
///   time, and this module emits none from it. `Present` is all it supports.
///
/// Before this existed, an Amcache entry raised a finding titled
/// "`name` ran, and no file entry for it was recovered", observing that
/// "AmcacheEntry records that `name` was run on this machine" and inferring
/// that the program "ran and … was removed after it ran". Every clause of that
/// was an execution claim built from a presence record, in the observation
/// field of a document written to be read out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimBasis {
    /// The record exists because the program was prepared for execution.
    Executed,
    /// The record exists because Windows catalogued the file. It says nothing
    /// about the file having run.
    Present,
}

/// A record naming a program on this machine, and what that record supports.
///
/// Extracted from one execution or inventory artifact by [`execution_claim`],
/// so the rules below never touch a metadata document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaim {
    /// What the source record establishes. See [`ClaimBasis`] — the finding's
    /// words follow from this and not from the fact that a record exists.
    pub basis: ClaimBasis,
    /// The artifact a finding about this claim should open — the file the
    /// program is, where the case knows it, else the execution record.
    pub subject: uuid::Uuid,
    /// Which artifact recorded the execution, in the vocabulary of its record
    /// type: `PrefetchEntry`, `AmcacheEntry`.
    pub source_record_type: String,
    /// The executable's file name, as the execution artifact stored it.
    pub image_name: String,
    /// The full path, where the execution artifact recorded one.
    pub image_path: Option<String>,
    /// Values worth carrying onto a finding: run count, last run, sha1.
    pub detail: Vec<(String, String)>,
    /// Byte offset on the backing device, where the record knows one.
    pub device_offset: Option<u64>,
}

/// What an execution artifact claims, or `None` when it is not one.
///
/// Reads only the keys the parser wrote. A prefetch file whose executable name
/// could not be read yields nothing rather than a claim about an unnamed
/// program.
pub fn execution_claim(artifact: &Artifact) -> Option<ExecutionClaim> {
    let record_type = meta_str(artifact, "type")?;
    let (basis, name, path) = match record_type.as_str() {
        "PrefetchEntry" => (
            ClaimBasis::Executed,
            meta_str(artifact, "executable_name")?,
            // A prefetch file names the volume separately from the path; the
            // full path is in `volumes` and is not reassembled here, because
            // the name is what the lookup uses and a half-built path in the
            // evidence field would be this tool's construction.
            None,
        ),
        // Presence, not execution. The keys this reader takes from Amcache —
        // `InventoryApplicationFile` and `File` — record that Windows saw the
        // file; neither carries a run count or a last-run time.
        "AmcacheEntry" => {
            let path = meta_str(artifact, "file_path")?;
            let name = path
                .rsplit(['\\', '/'])
                .next()
                .filter(|s| !s.is_empty())?
                .to_string();
            (ClaimBasis::Present, name, Some(path))
        }
        _ => return None,
    };

    let mut detail = Vec::new();
    for key in [
        "run_count",
        "last_execution_time",
        "key_last_written",
        "sha1_hash",
        "publisher",
        "program_id",
        "link_date",
        "file_size",
        "hive_name",
    ] {
        if let Some(v) = artifact.metadata.get(key) {
            if !v.is_null() {
                let rendered = v
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string());
                if !rendered.is_empty() {
                    detail.push((key.to_string(), rendered));
                }
            }
        }
    }

    Some(ExecutionClaim {
        basis,
        subject: subject_of(artifact),
        source_record_type: record_type,
        image_name: name,
        image_path: path,
        detail,
        device_offset: device_offset_of(artifact),
    })
}

/// What a name lookup answered for one executable name.
///
/// Mirrors `seance_db::FileNameMatches` without depending on it, so the rules
/// stay testable and this crate keeps no database dependency.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameLookup {
    /// Paths recovered for the name, as examples. May be a subset.
    pub paths: Vec<String>,
    /// How many entries carried the name in total.
    pub seen: usize,
    /// Every entry recovered for the name is a deleted one. **False when the
    /// lookup was capped**: the claim is about all of them.
    pub all_deleted: bool,
    /// The lookup returned a subset, so nothing may be concluded about the
    /// entries it did not read.
    pub truncated: bool,
}

/// How much of a filesystem the lookup was run against.
///
/// Carried into every finding because it is what the answer is worth. A case
/// with no file entries at all cannot answer "is this program on the volume",
/// and the difference between that and "looked and did not find it" is the
/// whole difference between a lead and a fabrication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemScope {
    /// File entries in the case when the question was asked.
    pub file_entries: i64,
}

impl FilesystemScope {
    /// Whether the question can be asked at all.
    pub fn can_answer(&self) -> bool {
        self.file_entries > 0
    }
}

/// Detection 3 and the "deleted-but-referenced" half of detection 6.
///
/// One pass over the execution claims, producing two different findings from
/// two different answers:
///
/// * **no file entry for the program at all** — the program ran and the
///   filesystem has no record of the file. [`Confidence::Notable`].
/// * **every file entry for it is deleted** — the program ran and the only
///   file entries naming it are deleted ones. [`Confidence::Notable`], and the
///   more interesting of the two in practice, because there is something left
///   to look at.
///
/// Claims whose name was found live raise nothing, which is the overwhelming
/// majority of a real case.
pub fn execution_without_a_live_file(
    claims: &[ExecutionClaim],
    lookup: &HashMap<String, NameLookup>,
    scope: FilesystemScope,
) -> Vec<Finding> {
    // No filesystem, no question. Returning findings here would report every
    // program the machine ever ran as absent from a volume nobody looked at.
    if !scope.can_answer() {
        return Vec::new();
    }
    let indexed = scope.file_entries;

    let mut out = Vec::new();
    for claim in claims {
        let key = claim.image_name.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        let found = lookup.get(&key);

        let mut evidence = vec![
            EvidenceItem::new("execution_record", claim.source_record_type.clone()),
            EvidenceItem::new("image_name", claim.image_name.clone()),
        ];
        if let Some(p) = &claim.image_path {
            evidence.push(EvidenceItem::new("image_path", p.clone()));
        }
        for (k, v) in &claim.detail {
            evidence.push(EvidenceItem::new(k.clone(), v.clone()));
        }
        evidence.push(EvidenceItem::new(
            "file_entries_searched",
            indexed.to_string(),
        ));

        match found {
            None => out.push(absent_binary(claim, evidence, indexed)),
            Some(hit) if hit.all_deleted => out.push(deleted_binary(claim, evidence, hit, indexed)),
            // Found, and at least one entry for it is live: nothing to raise.
            Some(_) => {}
        }
    }
    out
}

/// The sentence every one of these findings **opens** its qualification with.
///
/// It goes on both of them, because the misreading it guards against is the
/// same one in each: an Amcache entry read as an execution. A reader who knows
/// Amcache only by reputation will supply that reading unless the document
/// refuses it.
fn basis_note(basis: ClaimBasis) -> &'static str {
    match basis {
        ClaimBasis::Executed => {
            "A prefetch file exists because Windows prepared that image for execution, which a \
             service, a scheduled task or another program's child process does as readily as \
             somebody at the keyboard — so this says nothing about who ran it. "
        }
        ClaimBasis::Present => {
            "Amcache records that Windows catalogued the file, not that it ran: an entry is \
             written when the file is seen, and this finding must not be read as an execution. "
        }
    }
}

/// The sentence every one of these findings ends with. The comparison's own
/// bounds are worth more to a reader than the finding.
fn comparison_bound(indexed: i64) -> String {
    format!(
        "The comparison was made against the {indexed} file entries this case holds, by file \
         name only and not by path or hash, so a program present elsewhere under the same name \
         would have been found and one present under a different name would not."
    )
}

fn absent_binary(claim: &ExecutionClaim, evidence: Vec<EvidenceItem>, indexed: i64) -> Finding {
    let name = &claim.image_name;
    let source = &claim.source_record_type;
    // The kind, the title, the observation and the inference all follow from
    // what the source record supports. An Amcache entry supports none of the
    // execution wording.
    let (kind, title, observation, inference) = match claim.basis {
        ClaimBasis::Executed => (
            "execution_of_absent_binary",
            format!("{name} ran, and no file entry for it was recovered"),
            format!(
                "{source} records that {name} was run on this machine, and no file entry named \
                 {name} was recovered among the {indexed} file entries in this case — deleted \
                 entries included."
            ),
            "A program that ran and whose file is nowhere in the filesystem was removed after \
             it ran, and removed thoroughly enough that its file entry did not survive."
                .to_string(),
        ),
        ClaimBasis::Present => (
            "inventoried_binary_absent_from_filesystem",
            format!("Windows catalogued {name}, and no file entry for it was recovered"),
            format!(
                "{source} records that Windows catalogued a file named {name} on this machine, \
                 and no file entry under that name was recovered among the {indexed} file \
                 entries in this case — deleted entries included. **This is not a record of \
                 execution**: the Amcache keys read here carry no run count and no last-run \
                 time, and none is claimed."
            ),
            "A file Windows catalogued and that is nowhere in the filesystem was removed after \
             Windows saw it, and removed thoroughly enough that its file entry did not survive. \
             Whether it was ever run is a separate question this finding does not answer."
                .to_string(),
        ),
    };
    Finding {
        kind: kind.to_string(),
        title,
        subject_artifact: claim.subject,
        confidence: Confidence::Notable,
        observation,
        evidence,
        inference: Some(inference),
        qualification: format!(
            "{}This does not establish that the file was deleted to conceal it, or that it is \
             absent from the machine. Ordinary causes: it was on removable media or a network \
             share that is not part of this evidence; it was on a volume that was not acquired; \
             an uninstaller or an update removed it and its MFT record was reused; or the file \
             is present under a name this comparison did not match. {}",
            basis_note(claim.basis),
            comparison_bound(indexed)
        ),
        device_offset: claim.device_offset,
        source_module: CROSS_VIEW_MODULE_ID.to_string(),
    }
}

fn deleted_binary(
    claim: &ExecutionClaim,
    mut evidence: Vec<EvidenceItem>,
    hit: &NameLookup,
    indexed: i64,
) -> Finding {
    let name = &claim.image_name;
    evidence.push(EvidenceItem::new(
        "file_entries_named",
        hit.seen.to_string(),
    ));
    evidence.push(EvidenceItem::new("all_of_them_deleted", "true".to_string()));
    for path in &hit.paths {
        evidence.push(EvidenceItem::new("deleted_entry", path.clone()));
    }

    let source = &claim.source_record_type;
    let entries = hit.seen;
    let (plural, verb) = if entries == 1 {
        ("y", "is")
    } else {
        ("ies", "are")
    };
    let (kind, title, observation, inference, when) = match claim.basis {
        ClaimBasis::Executed => (
            "execution_of_deleted_binary",
            format!("{name} ran, and every file entry for it is deleted"),
            format!(
                "{source} records that {name} was run on this machine, and all {entries} file \
                 entr{plural} recovered under that name {verb} marked deleted."
            ),
            "The program ran and was then deleted. Unlike an absent file this one has \
             something left to examine: the deleted entry names its path and may still point \
             at recoverable content."
                .to_string(),
            "the deletion happened after the execution",
        ),
        ClaimBasis::Present => (
            "inventoried_binary_only_deleted_entries",
            format!("Windows catalogued {name}, and every file entry for it is deleted"),
            format!(
                "{source} records that Windows catalogued a file named {name} on this machine, \
                 and all {entries} file entr{plural} recovered under that name {verb} marked \
                 deleted. **This is not a record of execution**: the Amcache keys read here \
                 carry no run count and no last-run time, and none is claimed."
            ),
            "A file Windows catalogued was then deleted. Unlike an absent file this one has \
             something left to examine: the deleted entry names its path and may still point \
             at recoverable content. Whether it was ever run is a separate question this \
             finding does not answer."
                .to_string(),
            "the deletion happened after Windows catalogued it",
        ),
    };

    Finding {
        kind: kind.to_string(),
        title,
        subject_artifact: claim.subject,
        confidence: Confidence::Notable,
        observation,
        evidence,
        inference: Some(inference),
        qualification: format!(
            "{}This does not establish that the deletion was an attempt at concealment, or \
             that {when} — nothing here compared the two times. Uninstallers, updates and \
             temporary-file cleanup delete executables constantly. {} Open the deleted entries \
             named above and read their own timestamps and recovery state before relying on \
             this.",
            basis_note(claim.basis),
            comparison_bound(indexed)
        ),
        device_offset: claim.device_offset,
        source_module: CROSS_VIEW_MODULE_ID.to_string(),
    }
}

/// A delete the USN journal recorded.
///
/// Extracted from one `UsnJournalEntry` by [`usn_delete`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnDelete {
    /// The artifact a finding should open.
    pub subject: uuid::Uuid,
    /// The journal's own file reference: `record-sequence` for a V2 entry.
    pub file_reference: String,
    /// MFT record number from the reference.
    pub record_number: u64,
    /// Sequence number from the reference. `None` for a V3+ 128-bit
    /// reference, which this comparison cannot decompose and therefore
    /// refuses to compare.
    pub sequence_number: Option<u64>,
    /// The name the journal recorded for the file.
    pub file_name: String,
    /// The entry's USN and timestamp, for the evidence.
    pub detail: Vec<(String, String)>,
}

/// The delete a USN journal entry records, or `None` when it records something
/// else.
pub fn usn_delete(artifact: &Artifact) -> Option<UsnDelete> {
    if meta_str(artifact, "type").as_deref() != Some("UsnJournalEntry") {
        return None;
    }
    // `primary_operation` is the parser's own reduction of the reason flags.
    if meta_str(artifact, "primary_operation").as_deref() != Some("FILE_DELETE") {
        return None;
    }
    let file_reference = meta_str(artifact, "file_reference")?;
    let file_name = meta_str(artifact, "file_name")?;

    // V2: "record-sequence", both decimal. V3+: "LO-HI" in hex, which names a
    // 128-bit reference this comparison cannot decompose — recorded with no
    // sequence number so the rule below declines it rather than comparing
    // numbers that do not mean what it needs.
    let (record_number, sequence_number) = match file_reference.split_once('-') {
        Some((rec, seq)) => match (rec.parse::<u64>(), seq.parse::<u64>()) {
            (Ok(r), Ok(s)) => (r, Some(s)),
            _ => return None,
        },
        None => return None,
    };

    let mut detail = Vec::new();
    for key in [
        "usn",
        "timestamp",
        "reason_flags",
        "parent_reference",
        "file_attributes",
    ] {
        if let Some(v) = meta_str(artifact, key) {
            detail.push((key.to_string(), v));
        }
    }

    Some(UsnDelete {
        subject: subject_of(artifact),
        file_reference,
        record_number,
        sequence_number,
        file_name,
        detail,
    })
}

/// An MFT entry, reduced to what the comparison needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftEntry {
    /// The file entry's artifact id.
    pub artifact_id: uuid::Uuid,
    /// The MFT record number.
    pub record_number: u64,
    /// The record's sequence number, when the parser recorded one. The
    /// comparison is declined without it.
    pub sequence_number: Option<u64>,
    /// The name the MFT holds.
    pub name: String,
    /// Whether the MFT record is marked not in use.
    pub deleted: bool,
}

/// The "USN-vs-MFT" half of detection 6: the journal recorded a delete for a
/// file the MFT still describes as in use, at the same sequence number.
///
/// # Why the sequence number decides everything
///
/// An MFT record is reused. When a file is deleted its record is freed, and the
/// next file to take that record gets the same record number with the sequence
/// number incremented. So a journal delete for record 4,712 against a live MFT
/// record 4,712 is, in the ordinary case, **two different files** — and
/// reporting it would be a fabricated inconsistency on every busy volume.
///
/// The finding is raised only when record number *and* sequence number match
/// and the MFT says the record is in use: the journal and the MFT are then
/// describing the same instance of the same file and disagreeing about whether
/// it exists. A reference this build cannot decompose into the two numbers —
/// the V3+ 128-bit form — is declined rather than compared.
pub fn usn_delete_contradicting_mft(
    deletes: &[UsnDelete],
    mft: &HashMap<u64, Vec<MftEntry>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for d in deletes {
        let Some(seq) = d.sequence_number else {
            continue;
        };
        let Some(candidates) = mft.get(&d.record_number) else {
            continue;
        };
        for entry in candidates {
            if entry.sequence_number != Some(seq) || entry.deleted {
                continue;
            }
            let mut evidence = vec![
                EvidenceItem::new("usn_file_reference", d.file_reference.clone()),
                EvidenceItem::new("usn_file_name", d.file_name.clone()),
                EvidenceItem::new("mft_record_number", entry.record_number.to_string()),
                EvidenceItem::new("mft_sequence_number", seq.to_string()),
                EvidenceItem::new("mft_name", entry.name.clone()),
                EvidenceItem::new("mft_record_in_use", "true"),
            ];
            for (k, v) in &d.detail {
                evidence.push(EvidenceItem::new(k.clone(), v.clone()));
            }

            out.push(Finding {
                kind: "usn_delete_contradicts_mft".to_string(),
                title: format!(
                    "The journal deleted {}, and the MFT still holds it",
                    d.file_name
                ),
                subject_artifact: entry.artifact_id,
                confidence: Confidence::Notable,
                observation: format!(
                    "The USN journal records a FILE_DELETE for file reference {} — MFT record \
                     {} at sequence {} — and MFT record {} at that same sequence is marked in \
                     use, holding {}. The two views of this volume disagree about whether this \
                     file exists.",
                    d.file_reference, entry.record_number, seq, entry.record_number, entry.name
                ),
                evidence,
                inference: Some(
                    "An MFT record is freed by a delete and its sequence number increments \
                     when it is reused, so a live record at the sequence the journal deleted \
                     is the same instance of the same file described two ways. One of the two \
                     structures was modified after the other was written."
                        .to_string(),
                ),
                qualification:
                    "This does not establish that either structure was tampered with, or which \
                     of the two is right. The ordinary cause is acquisition order: the MFT and \
                     the journal are separate files, and an image taken from a running volume \
                     can capture one before a change and the other after it, so a file deleted \
                     during the acquisition appears exactly like this. Recovering a deleted \
                     record whose sequence had not yet been written, or a partly replayed \
                     journal, produce it too. What it does establish is that these two accounts \
                     of this file cannot both be quoted: read both records before relying on \
                     either."
                        .to_string(),
                // The subject is the MFT entry, which carries its own offset.
                device_offset: None,
                source_module: CROSS_VIEW_MODULE_ID.to_string(),
            });
        }
    }
    out
}
