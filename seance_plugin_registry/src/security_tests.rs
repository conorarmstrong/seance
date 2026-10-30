//! Registry key security — what this has to do, stated before it did it.
//!
//! # The two questions
//!
//! An examiner asks "who could have written this key?" and, when the answer is
//! not shown, "is that because the hive says nothing, or because this tool
//! could not read it?" Both are answered here, and the second is the reason the
//! per-key state has three values rather than two.
//!
//! # Where the fixtures come from
//!
//! The real hives under `reference/plaso/test_data/`, gated on
//! `SEANCE_REGISTRY_CORPUS`. Their ground truth was extracted cell by cell
//! before any of this was written: 334,111 key nodes over 820 descriptors,
//! every `nk` naming an allocated `sk`, and every cell's reference count equal
//! to the number of keys pointing at it exactly.
//!
//! That last equality is what makes the whole population trustworthy without a
//! second tool to compare against — and there is no second registry-ACL reader
//! on this machine (`regipy`, `python-registry` and `reglookup` are all absent,
//! which is recorded as a blocker in the roadmap).

use super::security::{stamp_key_security, KeySecurity};
use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::ForensicsModule;
use std::sync::Arc;
use uuid::Uuid;

use seance_core::data_source::ByteSliceDataSource;

/// A hive from the corpus named by `SEANCE_REGISTRY_CORPUS`, or `None` when the
/// gate is not provisioned. Named-but-missing panics: a pass would report a
/// comparison that never ran.
fn corpus_hive(name: &str) -> Option<Vec<u8>> {
    let dir = std::env::var("SEANCE_REGISTRY_CORPUS").ok()?;
    let path = std::path::Path::new(&dir).join(name);
    assert!(
        path.is_file(),
        "{} is missing from the corpus named by SEANCE_REGISTRY_CORPUS. The gate is ON and \
         cannot open — a pass here would report a comparison that never ran.",
        path.display()
    );
    Some(std::fs::read(&path).expect("read the corpus hive"))
}

/// Drive the parser over a hive's bytes and return the `RegistryHive` record.
fn hive_record(name: &str, bytes: Vec<u8>) -> serde_json::Value {
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(source),
        serde_json::json!({ "name": name, "path": format!("/Windows/System32/config/{name}") }),
    );
    let out = RegistryParser.process(&art).expect("the parser runs");
    out.into_iter()
        .map(|a| a.metadata)
        .find(|m| m["type"] == "RegistryHive")
        .expect("a RegistryHive record")
}

// --- The per-key state ------------------------------------------------------

/// Every key in a real hive must state its security, and on these hives every
/// one of them states `recorded`.
///
/// Not one of the 334,111 key nodes in the twelve corpus hives records no
/// descriptor or an unreadable one, so anything else here is a regression in
/// the reader rather than a property of the evidence.
#[test]
fn every_key_in_a_real_hive_states_its_security() {
    let Some(bytes) = corpus_hive("SAM") else {
        return;
    };
    let rec = hive_record("SAM", bytes);
    let keys = rec["all_keys"].as_array().expect("all_keys");
    assert!(!keys.is_empty());
    for key in keys {
        let state = key["security"].as_str().unwrap_or("");
        assert_eq!(
            state, "recorded",
            "key {:?} reported security {state:?}; every key in this hive names a readable \
             descriptor",
            key["key_path"]
        );
        assert!(
            key["security_descriptor_cell"].is_u64(),
            "a recorded descriptor must carry the cell that identifies it, so that two keys \
             sharing an ACL can be seen to share it: {:?}",
            key["key_path"]
        );
    }
}

/// The hive record must carry the distinct descriptor population, and its
/// reference counts must account for every key that named one.
///
/// This is the consistency check that stands in for a second tool. `SAM` holds
/// two descriptors whose counts are 1 and 64; the walk sees 65 keys naming a
/// descriptor.
#[test]
fn the_descriptor_population_accounts_for_every_key_that_named_one() {
    for (name, descriptors) in [("SAM", 2usize), ("NTUSER.DAT", 11)] {
        let Some(bytes) = corpus_hive(name) else {
            return;
        };
        let rec = hive_record(name, bytes);
        let sds = rec["security_descriptors"].as_array().expect("descriptors");
        assert_eq!(sds.len(), descriptors, "{name}: distinct descriptor count");

        let summary = &rec["key_security"];
        assert_eq!(
            summary["distinct_descriptors"],
            serde_json::json!(descriptors)
        );
        assert_eq!(
            summary["security_complete"],
            serde_json::json!(true),
            "{name}: nothing about this hive's security was unreadable, and the record must \
             say so rather than leave it to be inferred"
        );
        assert_eq!(
            summary["keys_with_unreadable_security"],
            serde_json::json!(0)
        );

        // Every descriptor's declared count must equal what the walk saw. In
        // all twelve corpus hives it does, exactly.
        for d in sds {
            assert_eq!(
                d["reference_count"], d["keys_referencing"],
                "{name}: cell {:?} declares {:?} references and the walk found {:?}",
                d["cell_offset"], d["reference_count"], d["keys_referencing"]
            );
            assert!(
                d["reference_count_disagrees_with_walk"].is_null(),
                "{name}: no disagreement should be flagged when the counts match"
            );
        }
        let walked: u64 = sds
            .iter()
            .map(|d| d["keys_referencing"].as_u64().unwrap_or(0))
            .sum();
        assert_eq!(
            summary["keys_with_security"].as_u64(),
            Some(walked),
            "{name}: the summary's count must be the sum of the population's"
        );
    }
}

/// The decoded ACL must be registry-shaped, and `SAM`'s must say what the real
/// `SAM` says.
///
/// The known answer, hand-decoded before the code existed: the root key's
/// descriptor is owned by `S-1-5-32-544` and grants `BUILTIN\Users`
/// `0x00020019` (`KEY_READ`); the descriptor its 64 children share does not
/// name `Users` at all. That is real Windows hardening, and it is the sentence
/// this whole item exists to make readable.
#[test]
fn the_real_sam_descriptors_decode_to_registry_rights() {
    let Some(bytes) = corpus_hive("SAM") else {
        return;
    };
    let rec = hive_record("SAM", bytes);
    let sds = rec["security_descriptors"].as_array().expect("descriptors");

    let root = sds
        .iter()
        .find(|d| d["reference_count"] == serde_json::json!(1))
        .expect("the descriptor named by one key");
    let children = sds
        .iter()
        .find(|d| d["reference_count"] == serde_json::json!(64))
        .expect("the descriptor named by 64 keys");

    for d in [root, children] {
        assert_eq!(
            d["owner"],
            serde_json::json!("S-1-5-32-544"),
            "both SAM descriptors are owned by BUILTIN\\Administrators"
        );
        assert_eq!(d["dacl_state"], serde_json::json!("present"));
        let summary = d["permission_summary"].as_str().unwrap_or("");
        // Registry rights, not file rights. The file table would have named
        // KEY_ALL_ACCESS's low bits as "Read Data / Write Data / ...".
        assert!(
            !summary.contains("Read Data") && !summary.contains("List Directory"),
            "a key's ACL must not be rendered with file rights: {summary:?}"
        );
    }

    let root_summary = root["permission_summary"].as_str().unwrap_or("");
    assert!(
        root_summary.contains("0x00020019"),
        "the SAM root grants BUILTIN\\Users KEY_READ, and the mask must be shown: {root_summary:?}"
    );
    assert!(
        root_summary.contains("inherit-only"),
        "four of this descriptor's eight ACEs are inherit-only and must be marked as not \
         applying to the key itself: {root_summary:?}"
    );
    let child_summary = children["permission_summary"].as_str().unwrap_or("");
    assert!(
        !child_summary.contains("0x00020019"),
        "the 64 keys beneath SAM's root are NOT readable by Users, which is the point of the \
         hardening: {child_summary:?}"
    );
}

/// A descriptor carried by exactly one key is recorded as such — an
/// observation, and deliberately not a finding.
#[test]
fn a_descriptor_carried_by_one_key_is_marked_and_not_judged() {
    let Some(bytes) = corpus_hive("SAM") else {
        return;
    };
    let rec = hive_record("SAM", bytes);
    let sds = rec["security_descriptors"].as_array().expect("descriptors");
    let singleton = sds
        .iter()
        .find(|d| d["keys_referencing"] == serde_json::json!(1))
        .expect("SAM's root descriptor is named by one key");
    assert_eq!(singleton["unique_to_one_key"], serde_json::json!(true));

    // No grade, no score, no verdict anywhere in the record. A widened-ACL
    // lead is a scored judgement and belongs to something that has measured
    // its false-positive rate (HUNT-122).
    let text = serde_json::to_string(&rec).expect("serialise");
    for forbidden in [
        "\"confidence\"",
        "\"finding_kind\"",
        "\"grade\"",
        "suspicious",
    ] {
        assert!(
            !text.contains(forbidden),
            "the hive record must not carry a judgement about an ACL: found {forbidden}"
        );
    }
}

// --- The absence paths, as pure functions -----------------------------------
//
// Every one of the 334,111 key nodes in the twelve corpus hives names a
// readable descriptor, so neither absence path can be reached from real
// evidence on this machine. They are pinned directly instead. Building a
// synthetic hive to reach them through the walk would test the fixture as much
// as the code, and the state machine is where the decision lives.

/// A key that records no descriptor says so, and says what the absence does
/// **not** mean.
///
/// "No ACL shown" must never read as "anyone may write this key". What the
/// absence means is that the hive holds no ACL for it — and what governed
/// access is then simply not in this evidence.
#[test]
fn a_key_recording_no_descriptor_says_what_the_absence_does_not_mean() {
    let mut key = serde_json::json!({ "key_path": "ROOT\\Run" });
    stamp_key_security(&mut key, &KeySecurity::NoneRecorded);
    assert_eq!(key["security"], serde_json::json!("none_recorded"));
    let note = key["security_note"].as_str().unwrap_or("");
    assert!(note.contains("not in this evidence"), "got {note:?}");
    assert!(
        key["security_incomplete"].is_null(),
        "an absent descriptor is a complete answer, not an incomplete one: nothing failed"
    );
    assert!(
        key["security_descriptor_cell"].is_null(),
        "there is no cell to name"
    );
}

/// A key whose descriptor would not read is **incomplete**, in the vocabulary
/// the API and the export honesty paths already read.
///
/// This is the distinction the three-state design exists for: "the hive says
/// nothing" and "this tool could not read it" must not render the same way,
/// and only the second is a gap in the inventory.
#[test]
fn a_key_whose_descriptor_will_not_read_is_scoped_incomplete() {
    let mut key = serde_json::json!({ "key_path": "ROOT\\Run" });
    stamp_key_security(
        &mut key,
        &KeySecurity::Unreadable {
            reason: "key security descriptor needs byte 20, but the hive holds only 8 bytes"
                .to_string(),
        },
    );
    assert_eq!(key["security"], serde_json::json!("unreadable"));
    assert_eq!(key["security_incomplete"], serde_json::json!(true));
    assert_eq!(
        key["security_incomplete_reason"],
        serde_json::json!("unresolved_structure"),
        "the reason must come from the shared IncompleteReason vocabulary"
    );
    assert!(
        key["security_incomplete_detail"]
            .as_str()
            .unwrap_or("")
            .contains("holds only 8 bytes"),
        "the refusal that caused it must be carried, not summarised away"
    );
    assert!(
        key["security_note"].is_null(),
        "an unreadable descriptor must not carry the absence note: it is not absent"
    );
}

/// The three states report three different words, and nothing collapses them.
#[test]
fn the_three_security_states_are_three_words() {
    assert_eq!(
        KeySecurity::Recorded { cell_offset: 0x160 }.as_str(),
        "recorded"
    );
    assert_eq!(KeySecurity::NoneRecorded.as_str(), "none_recorded");
    assert_eq!(
        KeySecurity::Unreadable {
            reason: String::new()
        }
        .as_str(),
        "unreadable"
    );
}

/// CR-047. SYNTHETIC: a source whose every read fails. An unreadable header
/// is "could not look", never "not this format": `process` must return the
/// error, not an empty success a report would read as "no such artefact".
#[test]
fn an_unreadable_header_is_could_not_look_not_not_this_format() {
    use seance_core::test_support::UnreadableSource;
    let ds: std::sync::Arc<dyn seance_core::data_source::DataSource> =
        std::sync::Arc::new(UnreadableSource::new(4096));
    let art = seance_core::artifact::Artifact::new(
        uuid::Uuid::new_v4(),
        seance_core::artifact::ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": "SYSTEM" }),
    );
    let out = crate::RegistryParser.process(&art);
    assert!(
        matches!(out, Err(seance_core::module::ModuleError::IoError(_))),
        "an unreadable header must be an error, got {out:?}"
    );
}
