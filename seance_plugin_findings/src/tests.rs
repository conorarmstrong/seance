//! What a detection module must and must not raise.
//!
//! The assertion carrying the most weight here is
//! [`weak_indicators_alone_raise_nothing`]. `HUNT-051` measured the naive
//! `$SI`/`$FN` rule at 4,054 of 25,018 files on a stock Windows XP install. A
//! triage list is read top-down by someone deciding where to spend the next
//! hour, so a detection that fires on a sixth of a clean disk does not merely
//! add noise — it buries the one file that matters and teaches its reader that
//! the list is not worth reading.

use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::finding::{Confidence, FINDING_RECORD_TYPE};
use seance_core::module::ForensicsModule;
use serde_json::json;
use uuid::Uuid;

/// A file entry as the MFT parser writes one: the verdict, its reasons and
/// the `$SI` times under their plain names, the `$FN` times prefixed.
fn fn_record(metadata: serde_json::Value) -> Artifact {
    Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, None, metadata)
}

#[test]
fn a_strong_indicator_becomes_a_ranked_lead_with_its_evidence() {
    let a = fn_record(json!({
        "name": "svchost.exe",
        "timestomp_suspected": true,
        "timestomp_reasons": ["SI ChangeTime is a whole second and precedes FN Created"],
        "timestamp_indicators": [
            {
                "reason": "SI ChangeTime is a whole second and precedes FN Created",
                "strength": "strong",
                "also_produced_by": null
            },
            {
                "reason": "SI Modified precedes FN Created",
                "strength": "weak",
                "also_produced_by": "a copy"
            }
        ],
        "modified": "2019-03-02T11:14:08Z",
        "fn_created": "2021-07-19T08:02:55Z",
    }));

    let findings = TimestompFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];

    assert_eq!(f.kind, "timestomp");
    assert!(f.title.contains("svchost.exe"));
    // Notable, never Strong: "no ordinary operation produces this" is not
    // "a person did this".
    assert_eq!(f.confidence, Confidence::Notable);

    // The observation names the indicator and is checkable.
    assert!(f.observation.contains("ChangeTime"), "{}", f.observation);
    // The inference is separate and reads as a reading, not a fact.
    assert!(f.inference.as_ref().unwrap().contains("hidden"));
    // The qualification names the ordinary causes and the HUNT-051 trade.
    assert!(f.qualification.contains("restore from backup"));
    assert!(f.qualification.contains("sixth of all files"));

    // The values it rests on travel with it, including the timestamps and
    // every indicator the parser found — the weak one labelled as weak.
    let named: Vec<&str> = f.evidence.iter().map(|e| e.name.as_str()).collect();
    assert!(named.contains(&"si_modified"));
    assert!(named.contains(&"fn_created"));
    assert!(
        f.evidence
            .iter()
            .any(|e| e.name.contains("weak") && e.value.contains("SI Modified")),
        "the weak indicators inform a reader who is now looking: {:?}",
        f.evidence
    );
}

/// HUNT-051, as a guard rather than a comment.
#[test]
fn weak_indicators_alone_raise_nothing() {
    // Exactly what a copied file looks like on a stock Windows install: the
    // parser records the asymmetry and returns no verdict.
    let a = fn_record(json!({
        "name": "shell32.dll",
        "timestomp_suspected": false,
        "timestomp_reasons": [],
        "timestamp_indicators": [
            {
                "reason": "SI Modified precedes FN Created",
                "strength": "weak",
                "also_produced_by": "a copy, which preserves the source's modification time"
            }
        ],
    }));
    assert!(
        TimestompFindings::new().findings_for(&a).is_empty(),
        "a copied file must not reach the triage list"
    );
}

/// A verdict this module cannot explain is a verdict it will not repeat.
#[test]
fn a_verdict_with_no_recorded_reasons_raises_nothing() {
    let a = fn_record(json!({
        "name": "mystery.bin",
        "timestomp_suspected": true,
        "timestomp_reasons": [],
    }));
    assert!(
        TimestompFindings::new().findings_for(&a).is_empty(),
        "a finding that could say only \"the parser said so\" is not checkable"
    );
}

#[test]
fn an_ordinary_record_raises_nothing() {
    for metadata in [
        json!({ "name": "a.txt" }),
        json!({ "type": "WhatsApp", "body": "hello" }),
        json!({ "name": "b.txt", "timestomp_suspected": false }),
    ] {
        assert!(TimestompFindings::new()
            .findings_for(&fn_record(metadata))
            .is_empty());
    }
}

/// The finding reaches the pipeline as an ordinary parsed record, so the
/// database, the search index, the viewers and the pivot all get it for free.
#[test]
fn a_finding_is_emitted_as_a_parsed_record_carrying_its_grade() {
    let a = fn_record(json!({
        "name": "svchost.exe",
        "timestomp_suspected": true,
        "timestomp_reasons": ["SI ChangeTime is a whole second and precedes FN Created"],
        "device_offset": 1_048_576,
    }));

    let out = TimestompFindings::new().process(&a).expect("processed");
    assert_eq!(out.len(), 1);
    let rec = &out[0];
    assert_eq!(rec.artifact_type, ArtifactType::ParsedRecord);
    assert_eq!(rec.parent_id, Some(a.id));
    assert_eq!(rec.metadata["type"], FINDING_RECORD_TYPE);
    assert_eq!(rec.metadata["finding_kind"], "timestomp");
    assert_eq!(rec.metadata["grade"], "investigative_lead");
    assert_eq!(rec.metadata["confidence"], "notable");
    // The device offset the subject knew is carried through.
    assert_eq!(rec.metadata["device_offset"], 1_048_576);
}

/// HUNT-152: the file entry is the file, so the finding names it, not the
/// `$MFT` the entry was parsed from.
#[test]
fn a_finding_names_the_file_entry_it_was_raised_on() {
    let mft_id = Uuid::new_v4();
    let mut entry = fn_record(json!({
        "name": "svchost.exe",
        "timestomp_suspected": true,
        "timestomp_reasons": ["SI ChangeTime is a whole second and precedes FN Created"],
    }));
    entry.parent_id = Some(mft_id);

    let findings = TimestompFindings::new().findings_for(&entry);
    assert_eq!(findings[0].subject_artifact, entry.id);
}

/// HUNT-152: the module must be dispatched the record type that carries the
/// verdict.
#[test]
fn the_timestomp_module_subscribes_to_the_file_entry_the_mft_parser_writes() {
    assert_eq!(
        TimestompFindings::new().subscribes_to(),
        vec![ArtifactType::FileEntry]
    );
}

/// Offset 0 is a real place on the device; "not known" must not render as it.
#[test]
fn a_finding_with_no_known_offset_carries_none() {
    let a = fn_record(json!({
        "name": "svchost.exe",
        "timestomp_suspected": true,
        "timestomp_reasons": ["SI ChangeTime is a whole second and precedes FN Created"],
    }));
    let findings = TimestompFindings::new().findings_for(&a);
    assert_eq!(findings[0].device_offset, None);
    assert!(findings[0].to_metadata()["device_offset"].is_null());
}
