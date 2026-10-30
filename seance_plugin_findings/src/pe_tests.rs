//! What the PE detections must and must not raise.
//!
//! Two assertions here are load-bearing rather than incidental.
//! [`a_partially_read_executable_raises_no_tampering_finding`] guards the claim
//! with the most damage in it: "this file does not match its signature" is an
//! allegation of tampering, and a truncated acquisition produces exactly that
//! comparison result on an untouched binary.
//! [`entropy_alone_is_the_weakest_lead_there_is`] pins the packing finding at
//! the bottom of the scale, because a detection that ranks an installer beside
//! a signature mismatch makes the ranking worthless.

use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::finding::{Confidence, FINDING_RECORD_TYPE};
use seance_core::module::ForensicsModule;
use serde_json::json;
use uuid::Uuid;

/// A `PeSignature` record as the PE plugin writes one.
fn pe_record(extra: serde_json::Value) -> Artifact {
    let mut m = json!({
        "type": "PeSignature",
        "subtype": "pe_analysis",
        "source_name": "svchost.exe",
        "machine": "x64 (AMD64)",
        "subsystem": "Windows Console",
    });
    let obj = m.as_object_mut().unwrap();
    for (k, v) in extra.as_object().unwrap() {
        obj.insert(k.clone(), v.clone());
    }
    Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, m)
}

fn kinds(a: &Artifact) -> Vec<String> {
    PeFindings::new()
        .findings_for(a)
        .into_iter()
        .map(|f| f.kind)
        .collect()
}

#[test]
fn a_signature_that_does_not_match_the_bytes_is_the_strongest_lead_raised() {
    let a = pe_record(json!({
        "signed": true,
        "signature_integrity": "MISMATCH — file does not match its signature",
        "publisher": "Microsoft Windows",
        "cert_issuer": "Microsoft Windows Production PCA 2011",
        "digest_algorithm": "sha256",
        "imphash": "a9f3b1c0e2d4567890abcdef12345678",
    }));

    let findings = PeFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1, "{:?}", kinds(&a));
    let f = &findings[0];
    assert_eq!(f.kind, "pe_signature_mismatch");
    assert_eq!(f.confidence, Confidence::Strong);
    // The observation states the comparison, so a reader knows it is a digest
    // comparison and not an operating-system trust decision.
    assert!(f.observation.contains("recomputed"), "{}", f.observation);
    // The qualification names the two ordinary causes and disclaims the trust
    // chain: the plugin's own documentation calls a wrong answer here a
    // fabricated allegation of tampering.
    assert!(f.qualification.contains("appended"));
    assert!(f.qualification.contains("trust"));
    // The signer travels with it: "which signature" is the first question.
    let named: Vec<&str> = f.evidence.iter().map(|e| e.name.as_str()).collect();
    assert!(named.contains(&"publisher"));
    assert!(named.contains(&"signature_integrity"));
}

/// The PE plugin withdraws the `signed` verdict on a short read (B2-052).
/// Nothing may reach the far stronger claim from the same incomplete bytes.
#[test]
fn a_partially_read_executable_raises_no_tampering_finding() {
    let a = pe_record(json!({
        "signature_integrity": "MISMATCH — file does not match its signature",
        "analysis_incomplete": true,
        "analysis_incomplete_reason": "short_read",
        "bytes_analysed": 4096,
        "declared_size": 1_200_000,
    }));
    assert!(
        kinds(&a).is_empty(),
        "an allegation of tampering must not be raised from bytes we did not read"
    );
}

/// Every inconclusive outcome the plugin writes reads "unverified (why)".
#[test]
fn an_unverified_signature_is_not_a_mismatch() {
    for integrity in [
        "unverified (signature not parseable)",
        "unverified (certificate table at offset 8192 declares 4096 bytes, outside the 6000 bytes analysed)",
        "unverified (unsupported digest algorithm)",
        "valid (bytes match the signed digest)",
    ] {
        let a = pe_record(json!({ "signature_integrity": integrity }));
        assert!(kinds(&a).is_empty(), "{integrity}");
    }
}

#[test]
fn an_executable_in_an_alternate_data_stream_names_the_stream_and_its_host() {
    let a = pe_record(json!({
        "source_name": "report.docx:update",
        "in_alternate_data_stream": true,
        "stream_name": "update",
        "parent_file": "report.docx",
        "signed": false,
        "signature_integrity": "unverified (no indirect-data digest)",
    }));

    let findings = PeFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1, "{:?}", kinds(&a));
    let f = &findings[0];
    assert_eq!(f.kind, "pe_in_alternate_data_stream");
    assert_eq!(f.confidence, Confidence::Notable);
    assert!(
        f.observation.contains("report.docx:update"),
        "{}",
        f.observation
    );
    // Both halves of the address are evidence: the stream's name is how a
    // reader recognises Zone.Identifier and the products that use streams.
    let named: Vec<&str> = f.evidence.iter().map(|e| e.name.as_str()).collect();
    assert!(named.contains(&"stream_name"));
    assert!(named.contains(&"parent_file"));
    assert!(f.qualification.contains("Zone.Identifier"));
    // An executable in a stream is not evidence it ran, and the finding says
    // so rather than leaving the reader to supply it.
    assert!(f.qualification.contains("prefetch"), "{}", f.qualification);
}

/// The PE plugin stamps the provenance; without the stamp there is no finding,
/// because a parsed record cannot see the file it came from.
#[test]
fn an_ordinary_executable_raises_nothing() {
    for extra in [
        json!({ "signed": true, "signature_integrity": "valid (bytes match the signed digest)" }),
        json!({ "signed": false }),
        json!({ "is_ads": true }), // the source's key, not the record's
        json!({ "likely_packed": false, "max_section_entropy": 6.1 }),
    ] {
        let a = pe_record(extra.clone());
        assert!(kinds(&a).is_empty(), "{extra}");
    }
}

/// A record from another parser must not be read as a PE record.
#[test]
fn only_a_pe_record_is_examined() {
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "NtfsFileName",
            "name": "notes.txt",
            "signature_integrity": "MISMATCH — file does not match its signature",
        }),
    );
    assert!(kinds(&a).is_empty());
}

#[test]
fn an_executable_carved_from_slack_says_whose_slack_and_qualifies_completeness() {
    let a = pe_record(json!({
        "source_name": "carved_1048576.exe",
        "carving_source": "slack",
        "parent_file": "readme.txt",
        "carving_offset_absolute": 1_048_576u64,
    }));

    let findings = PeFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1, "{:?}", kinds(&a));
    let f = &findings[0];
    assert_eq!(f.kind, "carved_executable_in_slack");
    assert_eq!(f.confidence, Confidence::Notable);
    assert!(f.observation.contains("readme.txt"), "{}", f.observation);
    // The offset the carver recorded is the finding's address on the device.
    assert_eq!(f.device_offset, Some(1_048_576));
    // A carve from slack is bounded by the slack window: the carver never reads
    // past the owner's last cluster, so the image is cut off there and its
    // imphash and signature describe the bytes recovered, not a whole file.
    assert!(
        f.qualification.contains("end of the cluster"),
        "{}",
        f.qualification
    );
    assert!(!f.qualification.contains("reused"), "{}", f.qualification);
    // A file starts at a cluster boundary, and the start of this cluster is the
    // live owner's content: under this volume's cluster size a PE header
    // part-way through it is not the start of a former file. The inference
    // must say what it can be, not that it is "the remains of one that was
    // deleted".
    let inference = f.inference.as_deref().unwrap_or_default();
    assert!(
        !inference.contains("remains of one that was deleted"),
        "{inference}"
    );
    assert!(inference.contains("cluster boundary"), "{inference}");
    assert!(inference.contains("embedded"), "{inference}");
    assert!(inference.contains("deliberately"), "{inference}");
    // "Cannot be the start of a file" holds only under this volume's cluster
    // geometry: a volume reformatted with larger clusters, or one that once
    // held another file system, can leave a former file starting at an old
    // boundary part-way through a current cluster. The inference must not
    // rule that out.
    assert!(
        !inference.contains("cannot be the start"),
        "an unqualified 'cannot' overstates: {inference}"
    );
    assert!(inference.contains("reformatted"), "{inference}");
    assert!(inference.contains("cluster size"), "{inference}");
}

/// The bottom rung of the scale exists for this detection.
#[test]
fn entropy_alone_is_the_weakest_lead_there_is() {
    let a = pe_record(json!({
        "likely_packed": true,
        "max_section_entropy": 7.94,
        "max_entropy_section": ".rsrc",
    }));

    let findings = PeFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1, "{:?}", kinds(&a));
    let f = &findings[0];
    assert_eq!(f.kind, "high_entropy_executable");
    assert_eq!(f.confidence, Confidence::Weak);
    // The number and the threshold are both in the observation: "high entropy"
    // is not checkable, "7.940 against 7.2" is.
    assert!(f.observation.contains("7.940"), "{}", f.observation);
    assert!(f.observation.contains("7.2"), "{}", f.observation);
    // And the qualification says outright that it is nearly worthless alone,
    // because an examiner ranking leads needs to know that.
    assert!(f.qualification.contains("installers"));
    assert!(
        f.qualification.contains("on its own"),
        "{}",
        f.qualification
    );
    // A missing version resource is part of the picture and is stated as
    // absent rather than omitted.
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "version_info" && e.value.contains("absent")));
}

/// `likely_packed` without the measurement behind it raises nothing: the
/// finding would state a verdict with no number to check it against.
#[test]
fn a_packing_verdict_with_no_entropy_recorded_raises_nothing() {
    let a = pe_record(json!({ "likely_packed": true }));
    assert!(kinds(&a).is_empty());
}

/// One executable can be several things at once, and the triage list wants all
/// of them — ranked, not merged.
#[test]
fn a_packed_unsigned_executable_in_a_stream_raises_each_lead_separately() {
    let a = pe_record(json!({
        "source_name": "invoice.pdf:x",
        "in_alternate_data_stream": true,
        "stream_name": "x",
        "parent_file": "invoice.pdf",
        "signature_integrity": "MISMATCH — file does not match its signature",
        "likely_packed": true,
        "max_section_entropy": 7.81,
        "max_entropy_section": ".text",
    }));
    let findings = PeFindings::new().findings_for(&a);
    let mut got: Vec<&str> = findings.iter().map(|f| f.kind.as_str()).collect();
    got.sort_unstable();
    assert_eq!(
        got,
        [
            "high_entropy_executable",
            "pe_in_alternate_data_stream",
            "pe_signature_mismatch"
        ]
    );
    // Strongest first is the API's job, but the ranks must differ or it has
    // nothing to sort by.
    assert_eq!(findings[0].confidence, Confidence::Strong);
    assert_eq!(findings[2].confidence, Confidence::Weak);
}

#[test]
fn each_finding_is_emitted_as_a_graded_parsed_record() {
    let a = pe_record(json!({
        "in_alternate_data_stream": true,
        "stream_name": "x",
        "parent_file": "invoice.pdf",
        "likely_packed": true,
        "max_section_entropy": 7.81,
        "max_entropy_section": ".text",
    }));
    let out = PeFindings::new().process(&a).expect("processed");
    assert_eq!(out.len(), 2);
    for rec in &out {
        assert_eq!(rec.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(rec.parent_id, Some(a.id));
        assert_eq!(rec.metadata["type"], FINDING_RECORD_TYPE);
        assert_eq!(rec.metadata["grade"], "investigative_lead");
        assert!(!rec.metadata["qualification"].as_str().unwrap().is_empty());
    }
}
