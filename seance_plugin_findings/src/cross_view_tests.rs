//! What the cross-view detections must and must not raise.
//!
//! Three assertions carry the weight.
//!
//! [`no_filesystem_means_no_answer_not_an_absence`]: a case with no file
//! entries cannot be asked whether a program is on the volume, and answering
//! anyway would report every program the machine ever ran as absent from a
//! volume nobody looked at.
//!
//! [`a_reused_mft_record_is_not_a_contradiction`]: an MFT record is reused, and
//! the sequence number is the only thing separating "the journal and the MFT
//! disagree about this file" from "these are two different files". Without that
//! check the detection would fire on every busy volume.
//!
//! [`a_capped_name_lookup_claims_nothing_about_what_it_did_not_read`]: "every
//! entry for this program is deleted" is a claim about all of them.

use crate::cross_view::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::finding::Confidence;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

fn record(metadata: serde_json::Value) -> Artifact {
    Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, metadata)
}

fn prefetch(name: &str) -> Artifact {
    record(json!({
        "type": "PrefetchEntry",
        "executable_name": name,
        "run_count": 4,
        "last_execution_time": "2026-03-02T11:14:08Z",
    }))
}

fn amcache(path: &str) -> Artifact {
    record(json!({
        "type": "AmcacheEntry",
        "file_path": path,
        "sha1_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "key_last_written": "2026-03-02T09:00:00Z",
    }))
}

const WHOLE_VOLUME: FilesystemScope = FilesystemScope {
    file_entries: 412_300,
};

fn live(paths: &[&str]) -> NameLookup {
    NameLookup {
        paths: paths.iter().map(|p| p.to_string()).collect(),
        seen: paths.len(),
        all_deleted: false,
        truncated: false,
    }
}

fn deleted(paths: &[&str]) -> NameLookup {
    NameLookup {
        paths: paths.iter().map(|p| p.to_string()).collect(),
        seen: paths.len(),
        all_deleted: true,
        truncated: false,
    }
}

// --- extracting the claim ----------------------------------------------------

#[test]
fn a_prefetch_record_claims_the_executable_it_names() {
    let a = prefetch("SVCHOST.EXE");
    let claim = execution_claim(&a).expect("a claim");
    assert_eq!(claim.image_name, "SVCHOST.EXE");
    assert_eq!(claim.source_record_type, "PrefetchEntry");
    // The run count and last-run time travel onto the finding: "it ran" is
    // worth more when it says how often and when.
    assert!(claim
        .detail
        .iter()
        .any(|(k, v)| k == "run_count" && v == "4"));
    assert!(claim.detail.iter().any(|(k, _)| k == "last_execution_time"));
    // A prefetch file names the volume separately from the path; a path
    // reassembled here would be this tool's construction, not the evidence.
    assert_eq!(claim.image_path, None);
}

#[test]
fn an_amcache_record_claims_the_basename_of_the_path_it_holds() {
    let claim = execution_claim(&amcache("c:\\windows\\temp\\dropper.exe")).expect("a claim");
    assert_eq!(claim.image_name, "dropper.exe");
    assert_eq!(
        claim.image_path.as_deref(),
        Some("c:\\windows\\temp\\dropper.exe")
    );
    assert!(claim.detail.iter().any(|(k, _)| k == "sha1_hash"));
}

/// The defect this guards against, which shipped.
///
/// Amcache's `InventoryApplicationFile` and `File` keys record that Windows
/// **catalogued** the file; they carry no run count and no last-run time, and
/// the reader emits none. The finding built from one was nevertheless titled
/// "`name` ran, and no file entry for it was recovered", observed that
/// "AmcacheEntry records that `name` was run on this machine" and inferred
/// that the program "ran and … was removed after it ran" — three execution
/// claims from a presence record, in a document written to be read out.
#[test]
fn an_amcache_claim_never_produces_execution_wording() {
    let claims = vec![
        execution_claim(&amcache("c:\\temp\\catalogued.exe")).unwrap(),
        execution_claim(&amcache("c:\\temp\\binned.exe")).unwrap(),
    ];
    assert!(claims.iter().all(|c| c.basis == ClaimBasis::Present));
    let mut lookup = HashMap::new();
    lookup.insert("binned.exe".to_string(), deleted(&["/tmp/binned.exe"]));
    let findings = execution_without_a_live_file(&claims, &lookup, WHOLE_VOLUME);
    assert_eq!(findings.len(), 2);

    for f in &findings {
        // The machine-readable field has to be true as well: somebody
        // filtering a case on `execution_*` must not be handed presence.
        assert!(
            f.kind.starts_with("inventoried_binary_"),
            "kind {} claims execution",
            f.kind
        );
        // The three constructions that shipped, each banned by name. A
        // blanket ban on the word "execution" would fail on the disclaimer
        // below, which has to say it.
        let inference = f.inference.as_ref().expect("an inference");
        for (field, text, banned) in [
            ("title", &f.title, " ran,"),
            ("observation", &f.observation, "was run on this machine"),
            ("inference", inference, "after it ran"),
            ("inference", inference, "program that ran"),
        ] {
            assert!(
                !text.contains(banned),
                "the {field} of an Amcache finding says {banned:?}: {text}"
            );
        }
        // And it says outright what it is not, because a reader who knows
        // Amcache only by reputation will supply the execution reading.
        assert!(
            f.observation.contains("not a record of execution"),
            "{}",
            f.observation
        );
        assert!(
            f.qualification
                .contains("catalogued the file, not that it ran"),
            "{}",
            f.qualification
        );
    }
    assert!(findings[0]
        .title
        .starts_with("Windows catalogued catalogued.exe"));
}

/// And the prefetch half still says "ran", because a prefetch file supports
/// it — while saying it cannot say who.
#[test]
fn a_prefetch_claim_still_says_the_program_ran_and_not_who_ran_it() {
    let claims = vec![execution_claim(&prefetch("ABSENT.EXE")).unwrap()];
    assert_eq!(claims[0].basis, ClaimBasis::Executed);
    let findings = execution_without_a_live_file(&claims, &HashMap::new(), WHOLE_VOLUME);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.kind, "execution_of_absent_binary");
    assert!(f.title.starts_with("ABSENT.EXE ran"));
    assert!(
        f.qualification.contains("says nothing about who ran it"),
        "{}",
        f.qualification
    );
}

/// Presence in the application-compatibility cache is not execution, and the
/// `exec_flag` read as such is a shim-database flag whose meaning varies by
/// Windows version. Reading it as execution would put a claim in the
/// observation field that the evidence does not support.
#[test]
fn a_shimcache_entry_is_not_an_execution_claim() {
    let a = record(json!({
        "type": "ShimcacheEntry",
        "path": "C:\\Windows\\Temp\\dropper.exe",
        "exec_flag": true,
    }));
    assert_eq!(execution_claim(&a), None);
}

#[test]
fn a_record_with_no_executable_name_makes_no_claim() {
    for metadata in [
        json!({ "type": "PrefetchEntry", "run_count": 1 }),
        json!({ "type": "AmcacheEntry", "sha1_hash": "abc" }),
        json!({ "type": "AmcacheEntry", "file_path": "" }),
        json!({ "type": "NtfsFileName", "name": "a.exe" }),
    ] {
        assert_eq!(
            execution_claim(&record(metadata.clone())),
            None,
            "{metadata}"
        );
    }
}

// --- detection 3 and the deleted-but-referenced half of 6 --------------------

#[test]
fn a_program_that_ran_with_no_file_entry_anywhere_is_a_notable_lead() {
    let claims = vec![execution_claim(&prefetch("DROPPER.EXE")).unwrap()];
    let findings = execution_without_a_live_file(&claims, &HashMap::new(), WHOLE_VOLUME);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.kind, "execution_of_absent_binary");
    assert_eq!(f.confidence, Confidence::Notable);
    // The size of the search is in the observation, because that is what the
    // answer is worth, and deleted entries were included in it.
    assert!(f.observation.contains("412300"), "{}", f.observation);
    assert!(
        f.observation.contains("deleted entries"),
        "{}",
        f.observation
    );
    // The qualification names removable media and a reused MFT record, and
    // concedes that the comparison was by name only.
    assert!(f.qualification.contains("removable media"));
    assert!(f.qualification.contains("by file name only"));
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "file_entries_searched" && e.value == "412300"));
}

#[test]
fn a_program_whose_only_file_entries_are_deleted_names_them() {
    let claims = vec![execution_claim(&prefetch("DROPPER.EXE")).unwrap()];
    let mut lookup = HashMap::new();
    lookup.insert(
        "dropper.exe".to_string(),
        deleted(&["/Users/jsmith/AppData/Local/Temp/dropper.exe"]),
    );

    let findings = execution_without_a_live_file(&claims, &lookup, WHOLE_VOLUME);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.kind, "execution_of_deleted_binary");
    assert_eq!(f.confidence, Confidence::Notable);
    // Singular reads as singular: a row quoted into a statement must not say
    // "all 1 file entries are".
    assert!(
        f.observation
            .contains("all 1 file entry recovered under that name is marked deleted"),
        "{}",
        f.observation
    );
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "deleted_entry" && e.value.ends_with("dropper.exe")));
    // Nothing here compared the deletion time to the execution time, and the
    // finding says so rather than letting the reader supply the order.
    assert!(
        f.qualification.contains("after the execution"),
        "{}",
        f.qualification
    );
}

#[test]
fn a_program_with_a_live_file_entry_raises_nothing() {
    let claims = vec![
        execution_claim(&prefetch("SVCHOST.EXE")).unwrap(),
        execution_claim(&amcache("c:\\program files\\vendor\\app.exe")).unwrap(),
    ];
    let mut lookup = HashMap::new();
    lookup.insert(
        "svchost.exe".to_string(),
        live(&["/Windows/System32/svchost.exe"]),
    );
    // One deleted copy and one live copy: the program is on the volume.
    lookup.insert(
        "app.exe".to_string(),
        NameLookup {
            paths: vec![
                "/Program Files/Vendor/app.exe".into(),
                "/Users/jsmith/AppData/Local/Temp/app.exe".into(),
            ],
            seen: 2,
            all_deleted: false,
            truncated: false,
        },
    );
    assert!(execution_without_a_live_file(&claims, &lookup, WHOLE_VOLUME).is_empty());
}

/// Answering this question against a case with no filesystem would report
/// every program the machine ever ran as absent from a volume nobody looked at.
#[test]
fn no_filesystem_means_no_answer_not_an_absence() {
    let claims = vec![execution_claim(&prefetch("DROPPER.EXE")).unwrap()];
    let none = FilesystemScope { file_entries: 0 };
    assert!(!none.can_answer());
    assert!(execution_without_a_live_file(&claims, &HashMap::new(), none).is_empty());
}

/// "Every entry for this program is deleted" is a claim about all of them, so
/// a lookup that read only some of them may not reach it. The database sets
/// `all_deleted` false whenever it truncated; this pins the rule on the side
/// that consumes it too.
#[test]
fn a_capped_name_lookup_claims_nothing_about_what_it_did_not_read() {
    let claims = vec![execution_claim(&prefetch("SETUP.EXE")).unwrap()];
    let mut lookup = HashMap::new();
    lookup.insert(
        "setup.exe".to_string(),
        NameLookup {
            paths: vec!["/a/setup.exe".into(), "/b/setup.exe".into()],
            seen: 2_431,
            all_deleted: false,
            truncated: true,
        },
    );
    assert!(execution_without_a_live_file(&claims, &lookup, WHOLE_VOLUME).is_empty());
}

// --- the USN/MFT half of detection 6 -----------------------------------------

fn usn_record(reference: &str, name: &str, op: &str) -> Artifact {
    record(json!({
        "type": "UsnJournalEntry",
        "record_type": "usn_journal",
        "usn": "184549376",
        "file_reference": reference,
        "parent_reference": "5-5",
        "file_name": name,
        "primary_operation": op,
        "reason_flags": "0x00000200",
        "timestamp": "2026-03-02T11:14:08Z",
    }))
}

fn mft(record_number: u64, sequence: Option<u64>, name: &str, deleted: bool) -> MftEntry {
    MftEntry {
        artifact_id: Uuid::new_v4(),
        record_number,
        sequence_number: sequence,
        name: name.to_string(),
        deleted,
    }
}

fn by_record(entries: Vec<MftEntry>) -> HashMap<u64, Vec<MftEntry>> {
    let mut m: HashMap<u64, Vec<MftEntry>> = HashMap::new();
    for e in entries {
        m.entry(e.record_number).or_default().push(e);
    }
    m
}

#[test]
fn a_journal_delete_against_a_live_mft_record_at_the_same_sequence_is_a_lead() {
    let d = usn_delete(&usn_record("4712-3", "notes.txt", "FILE_DELETE")).expect("a delete");
    assert_eq!(d.record_number, 4712);
    assert_eq!(d.sequence_number, Some(3));

    let mft_index = by_record(vec![mft(4712, Some(3), "notes.txt", false)]);
    let findings = usn_delete_contradicting_mft(&[d], &mft_index);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.kind, "usn_delete_contradicts_mft");
    assert_eq!(f.confidence, Confidence::Notable);
    // Both numbers are in the observation: the sequence is the whole of why
    // this is a contradiction rather than two different files.
    assert!(f.observation.contains("sequence 3"), "{}", f.observation);
    assert!(f.observation.contains("marked in\n use") || f.observation.contains("marked in use"));
    // Acquisition order is the ordinary cause and is named first.
    assert!(
        f.qualification.contains("acquisition order"),
        "{}",
        f.qualification
    );
    // The finding opens the MFT entry, because that is the record an examiner
    // needs to read against the journal.
    assert_eq!(f.subject_artifact, mft_index[&4712][0].artifact_id);
}

/// An MFT record is reused: the next file to take record 4,712 gets the same
/// record number with the sequence incremented. Reporting that as a
/// contradiction would fire on every busy volume.
#[test]
fn a_reused_mft_record_is_not_a_contradiction() {
    let d = usn_delete(&usn_record("4712-3", "notes.txt", "FILE_DELETE")).unwrap();
    // Same record, next sequence, live, different file: the normal case.
    let mft_index = by_record(vec![mft(4712, Some(4), "invoice.pdf", false)]);
    assert!(usn_delete_contradicting_mft(&[d], &mft_index).is_empty());
}

#[test]
fn an_mft_record_that_agrees_it_is_deleted_is_not_a_contradiction() {
    let d = usn_delete(&usn_record("4712-3", "notes.txt", "FILE_DELETE")).unwrap();
    let mft_index = by_record(vec![mft(4712, Some(3), "notes.txt", true)]);
    assert!(usn_delete_contradicting_mft(&[d], &mft_index).is_empty());
}

/// A reference this build cannot decompose into record and sequence is
/// declined, not compared: the V3+ 128-bit form's halves are not those two
/// numbers.
#[test]
fn a_reference_that_cannot_be_decomposed_is_declined() {
    let d = usn_delete(&usn_record("1268-A3F", "notes.txt", "FILE_DELETE"));
    assert_eq!(
        d, None,
        "hex halves of a 128-bit reference are not record-sequence"
    );

    // And an entry with a sequence number the parser did not record on the MFT
    // side is declined the same way.
    let d = usn_delete(&usn_record("4712-3", "notes.txt", "FILE_DELETE")).unwrap();
    let mft_index = by_record(vec![mft(4712, None, "notes.txt", false)]);
    assert!(usn_delete_contradicting_mft(&[d], &mft_index).is_empty());
}

#[test]
fn a_journal_entry_that_is_not_a_delete_is_not_examined() {
    for op in ["FILE_CREATE", "RENAME", "DATA_OVERWRITE", "CLOSE"] {
        assert_eq!(
            usn_delete(&usn_record("4712-3", "notes.txt", op)),
            None,
            "{op}"
        );
    }
    let a = record(json!({
        "type": "NtfsFileName",
        "primary_operation": "FILE_DELETE",
        "file_reference": "4712-3",
        "file_name": "notes.txt",
    }));
    assert_eq!(usn_delete(&a), None);
}

#[test]
fn a_journal_delete_for_a_record_the_mft_does_not_describe_raises_nothing() {
    let d = usn_delete(&usn_record("4712-3", "notes.txt", "FILE_DELETE")).unwrap();
    assert!(usn_delete_contradicting_mft(&[d], &HashMap::new()).is_empty());
}

/// Every cross-view finding is a lead like any other: graded, qualified, and
/// carrying the values it rests on.
#[test]
fn every_cross_view_finding_is_graded_and_qualified() {
    let claims = vec![
        execution_claim(&prefetch("ABSENT.EXE")).unwrap(),
        execution_claim(&prefetch("GONE.EXE")).unwrap(),
    ];
    let mut lookup = HashMap::new();
    lookup.insert("gone.exe".to_string(), deleted(&["/tmp/gone.exe"]));
    let mut findings = execution_without_a_live_file(&claims, &lookup, WHOLE_VOLUME);

    let d = usn_delete(&usn_record("4712-3", "notes.txt", "FILE_DELETE")).unwrap();
    let mft_index = by_record(vec![mft(4712, Some(3), "notes.txt", false)]);
    findings.extend(usn_delete_contradicting_mft(&[d], &mft_index));

    assert_eq!(findings.len(), 3);
    for f in &findings {
        let m = f.to_metadata();
        assert_eq!(m["grade"], "investigative_lead");
        assert!(!f.qualification.is_empty());
        assert!(!f.observation.is_empty());
        assert!(!f.evidence.is_empty());
        assert_eq!(f.source_module, CROSS_VIEW_MODULE_ID);
    }
}

/// `CROSS_VIEW_KINDS` stands in for the module registry, which cannot list
/// these detections because they are not modules. It is what `seance_api`
/// checks its declarations against, so it has to match what the functions
/// actually raise — in both directions.
#[test]
fn every_kind_this_module_raises_is_declared() {
    // One input that trips each rule. Prefetch and Amcache raise DIFFERENT
    // kinds from the same two answers, because one records an execution and
    // the other records that Windows saw the file.
    let claims = vec![
        execution_claim(&prefetch("ABSENT.EXE")).unwrap(),
        execution_claim(&prefetch("GONE.EXE")).unwrap(),
        execution_claim(&amcache("c:\\temp\\catalogued.exe")).unwrap(),
        execution_claim(&amcache("c:\\temp\\binned.exe")).unwrap(),
    ];
    let mut lookup = HashMap::new();
    lookup.insert("gone.exe".to_string(), deleted(&["/tmp/gone.exe"]));
    lookup.insert("binned.exe".to_string(), deleted(&["/tmp/binned.exe"]));
    let mut raised: Vec<String> = execution_without_a_live_file(&claims, &lookup, WHOLE_VOLUME)
        .into_iter()
        .map(|f| f.kind)
        .collect();

    let d = usn_delete(&usn_record("4712-3", "notes.txt", "FILE_DELETE")).unwrap();
    let mft_index = by_record(vec![mft(4712, Some(3), "notes.txt", false)]);
    raised.extend(
        usn_delete_contradicting_mft(&[d], &mft_index)
            .into_iter()
            .map(|f| f.kind),
    );

    raised.sort();
    raised.dedup();
    let mut declared: Vec<String> = CROSS_VIEW_KINDS.iter().map(|k| k.to_string()).collect();
    declared.sort();
    assert_eq!(
        raised, declared,
        "a kind raised but not declared makes an empty triage list read as \"nothing is wrong\"; \
         a kind declared but never raised tells an examiner this build looks for something it \
         does not"
    );
}
