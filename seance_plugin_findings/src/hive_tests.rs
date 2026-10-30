//! What the hive discrepancy detection must and must not raise.
//!
//! The assertion that matters most is
//! [`one_cause_produces_one_finding_however_many_keys_it_damaged`]. A torn
//! index root damages every key beneath it, and a triage list with three
//! hundred rows from one cause is worse than no list at all — the row that
//! matters is no longer findable in it.

use super::*;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::finding::{Confidence, FINDING_RECORD_TYPE};
use seance_core::module::ForensicsModule;
use serde_json::json;
use uuid::Uuid;

/// One key inside a hive record's `all_keys`.
fn key(path: &str, declared: u64, listed: Option<u64>) -> serde_json::Value {
    let mut k = json!({
        "key_path": path,
        "key_name": path.rsplit('\\').next().unwrap_or(path),
        "subkey_count": declared,
        "value_count": 0,
    });
    let obj = k.as_object_mut().unwrap();
    match listed {
        Some(n) => {
            obj.insert("subkeys_listed".into(), json!(n));
            if n != declared {
                obj.insert("subkey_count_disagrees_with_index".into(), json!(true));
            }
        }
        // A key declaring no subkeys has no index to have counted, so the key
        // is absent rather than zero.
        None => {
            obj.insert("subkeys_listed".into(), serde_json::Value::Null);
        }
    }
    k
}

fn hive_record(keys: Vec<serde_json::Value>) -> Artifact {
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RegistryHive",
            "hive_type": "SOFTWARE",
            "total_keys": keys.len(),
            "all_keys": keys,
        }),
    )
}

#[test]
fn a_hive_whose_keys_agree_with_their_indexes_raises_nothing() {
    let a = hive_record(vec![
        key("SOFTWARE\\Microsoft", 42, Some(42)),
        key("SOFTWARE\\Microsoft\\Windows", 7, Some(7)),
        key("SOFTWARE\\Vendor\\Leaf", 0, None),
    ]);
    assert!(HiveFindings::new().findings_for(&a).is_empty());
}

#[test]
fn a_key_that_counts_more_children_than_its_index_names_is_a_notable_lead() {
    let a = hive_record(vec![
        key("SOFTWARE\\Microsoft", 42, Some(42)),
        key("SOFTWARE\\Vendor\\Run", 9, Some(7)),
    ]);
    let findings = HiveFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.kind, "hive_subkey_count_discrepancy");
    assert_eq!(f.confidence, Confidence::Notable);
    // Both numbers are in the evidence against the key's own path, so the
    // observation can be checked against the hive record it points at.
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "SOFTWARE\\Vendor\\Run" && e.value == "declares 9, index names 7"));
    // The observation says which of the hive's two accounts the enumeration is.
    assert!(f.observation.contains("the index"), "{}", f.observation);
    // The inference is about deletion and is labelled as a reading.
    assert!(f.inference.as_ref().unwrap().contains("unallocated cells"));
    // The qualification names the ordinary cause, which is a dirty hive. This
    // record carries no replay provenance, so the qualification must not claim
    // either way whether the logs were replayed (HUNT-201).
    assert!(f.qualification.contains(".LOG1"), "{}", f.qualification);
    assert!(
        f.qualification
            .contains("does not say whether the transaction logs were replayed"),
        "{}",
        f.qualification
    );
    assert!(!f.qualification.contains("did not replay"));
    // A hive record covers a file: there is no single offset, and offset 0 is a
    // real place on the device.
    assert_eq!(f.device_offset, None);
}

/// Stamp the replay provenance onto a hive record exactly as the registry
/// plugin does (`seance_plugin_registry::txlog::stamp_replay_provenance`):
/// `logs_replayed`, `replay_reason`, `hive_dirty`, `log_format`, `log_files`
/// and the counters, on the `RegistryHive` record itself.
fn with_replay(
    mut a: Artifact,
    replayed: bool,
    dirty: bool,
    reason: &str,
    entries_applied: u64,
) -> Artifact {
    let m = a.metadata.as_object_mut().unwrap();
    m.insert("logs_replayed".into(), json!(replayed));
    m.insert("replay_reason".into(), json!(reason));
    m.insert("hive_dirty".into(), json!(dirty));
    m.insert(
        "log_format".into(),
        json!(if replayed { "new_hvle" } else { "none" }),
    );
    m.insert(
        "log_files".into(),
        json!(if replayed {
            vec!["SOFTWARE.LOG1", "SOFTWARE.LOG2"]
        } else {
            vec![]
        }),
    );
    m.insert("primary_sequence".into(), json!(412));
    m.insert(
        "secondary_sequence".into(),
        json!(if dirty { 409 } else { 412 }),
    );
    m.insert("log_entries_applied".into(), json!(entries_applied));
    m.insert("dirty_pages_applied".into(), json!(entries_applied * 3));
    a
}

fn qualification_for(a: &Artifact) -> String {
    let findings = HiveFindings::new().findings_for(a);
    assert_eq!(findings.len(), 1);
    findings[0].qualification.clone()
}

/// HUNT-201. A dirty hive whose logs the registry plugin DID replay: the
/// qualification must say so, and must not tell the report's reader the logs
/// were left unapplied.
#[test]
fn a_hive_whose_logs_were_replayed_is_not_qualified_as_unreplayed() {
    let a = with_replay(
        hive_record(vec![key("SOFTWARE\\Vendor\\Run", 9, Some(7))]),
        true,
        true,
        "recovered",
        3,
    );
    let q = qualification_for(&a);
    assert!(!q.contains("did not replay"), "{q}");
    assert!(
        q.contains("replayed the transaction logs before reading this hive"),
        "{q}"
    );
    assert!(q.contains("3 log entries"), "{q}");
    assert!(q.contains("survives the replay"), "{q}");
    let f = &HiveFindings::new().findings_for(&a)[0];
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "logs_replayed" && e.value == "true"));
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "replay_reason" && e.value == "recovered"));
}

/// A replay that stopped early applied part of the logs; the reason it stopped
/// is named, because the unapplied remainder may be what reconciles the counts.
#[test]
fn a_partial_replay_is_qualified_with_the_reason_it_stopped() {
    let a = with_replay(
        hive_record(vec![key("SOFTWARE\\Vendor\\Run", 9, Some(7))]),
        true,
        true,
        "sequence_gap",
        1,
    );
    let q = qualification_for(&a);
    assert!(!q.contains("did not replay"), "{q}");
    assert!(q.contains("stopped early"), "{q}");
    assert!(q.contains("sequence_gap"), "{q}");
}

/// A dirty hive whose logs were not replayed keeps the original sentence, and
/// now says why.
#[test]
fn a_dirty_hive_whose_logs_were_not_replayed_says_so_and_why() {
    let a = with_replay(
        hive_record(vec![key("SOFTWARE\\Vendor\\Run", 9, Some(7))]),
        false,
        true,
        "no_logs_found",
        0,
    );
    let q = qualification_for(&a);
    assert!(q.contains("did not replay them"), "{q}");
    assert!(q.contains("no_logs_found"), "{q}");
}

/// A clean hive had no pending writes: the dirty-hive explanation does not
/// apply to this copy, and the qualification must not offer it as the cause.
#[test]
fn a_clean_hive_is_not_qualified_with_the_unflushed_writes_explanation() {
    let a = with_replay(
        hive_record(vec![key("SOFTWARE\\Vendor\\Run", 9, Some(7))]),
        false,
        false,
        "clean",
        0,
    );
    let q = qualification_for(&a);
    assert!(!q.contains("did not replay"), "{q}");
    assert!(q.contains("records a clean flush"), "{q}");
}

/// The other direction is reported too: the reason a reader cares is that the
/// hive's two accounts differ, not which way round.
#[test]
fn an_index_holding_more_than_the_count_declares_is_reported_the_same_way() {
    let a = hive_record(vec![key("SOFTWARE\\Vendor", 3, Some(5))]);
    let findings = HiveFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1);
    // Nothing was lost, so the "declares more" count is zero and says so
    // rather than being omitted.
    assert!(findings[0]
        .evidence
        .iter()
        .any(|e| e.name == "keys_declaring_more_than_the_index_names" && e.value == "0"));
    assert!(findings[0].observation.contains("0 of them declare more"));
}

/// A torn index root damages every key beneath it. One cause, one row.
#[test]
fn one_cause_produces_one_finding_however_many_keys_it_damaged() {
    let mut keys: Vec<serde_json::Value> = (0..300)
        .map(|i| key(&format!("SOFTWARE\\Vendor\\Key{i}"), 4, Some(3)))
        .collect();
    keys.push(key("SOFTWARE\\Intact", 2, Some(2)));
    let a = hive_record(keys);

    let findings = HiveFindings::new().findings_for(&a);
    assert_eq!(findings.len(), 1, "one finding per hive, not per key");
    let f = &findings[0];
    assert!(f.title.starts_with("300 keys"), "{}", f.title);
    // The cap is disclosed with the full count, so the named subset cannot be
    // mistaken for the total.
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "keys_disagreeing" && e.value == "300"));
    let named = f
        .evidence
        .iter()
        .filter(|e| e.name.starts_with("SOFTWARE\\Vendor\\Key"))
        .count();
    assert_eq!(named, 10);
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "keys not named above" && e.value.contains("290")));
}

/// The keys that lost children are the ones where a deleted key's name may
/// still be recoverable, so they are named first when the cap bites.
#[test]
fn the_keys_that_lost_children_are_named_before_the_ones_that_gained() {
    let mut keys: Vec<serde_json::Value> = (0..12)
        .map(|i| key(&format!("SOFTWARE\\Gained{i}"), 1, Some(4)))
        .collect();
    keys.push(key("SOFTWARE\\Lost\\Badly", 50, Some(2)));
    keys.push(key("SOFTWARE\\Lost\\Slightly", 5, Some(4)));
    let a = hive_record(keys);

    let f = &HiveFindings::new().findings_for(&a)[0];
    let paths: Vec<&str> = f
        .evidence
        .iter()
        .filter(|e| e.name.starts_with("SOFTWARE\\"))
        .map(|e| e.name.as_str())
        .collect();
    assert_eq!(paths[0], "SOFTWARE\\Lost\\Badly");
    assert_eq!(paths[1], "SOFTWARE\\Lost\\Slightly");
}

/// A key whose subkey index would not read is short for a different reason,
/// and the two must not be conflated: one is a discrepancy, the other a hole.
#[test]
fn a_torn_subkey_index_is_counted_separately_from_the_discrepancy() {
    let mut torn = key("SOFTWARE\\Torn", 9, Some(7));
    torn.as_object_mut()
        .unwrap()
        .insert("subkeys_incomplete".into(), json!(true));
    let a = hive_record(vec![torn]);

    let f = &HiveFindings::new().findings_for(&a)[0];
    assert!(f
        .evidence
        .iter()
        .any(|e| e.name == "keys whose subkey index would not read" && e.value.starts_with("1;")));
}

#[test]
fn a_record_that_is_not_a_hive_is_not_examined() {
    for metadata in [
        json!({ "type": "NtfsFileName", "all_keys": [] }),
        json!({ "type": "RegistryHive", "hive_type": "SOFTWARE" }), // no all_keys
        json!({ "type": "RegistryHive", "all_keys": [] }),
    ] {
        let a = Artifact::new(Uuid::new_v4(), ArtifactType::ParsedRecord, None, metadata);
        assert!(HiveFindings::new().findings_for(&a).is_empty());
    }
}

/// A key stamped as disagreeing but carrying only one of the two numbers is
/// not reportable: the finding would state a discrepancy it cannot show.
#[test]
fn a_disagreement_missing_one_of_its_two_numbers_raises_nothing() {
    for k in [
        json!({ "key_path": "A", "subkey_count_disagrees_with_index": true, "subkey_count": 9 }),
        json!({ "key_path": "A", "subkey_count_disagrees_with_index": true, "subkeys_listed": 7 }),
    ] {
        let a = hive_record(vec![k]);
        assert!(HiveFindings::new().findings_for(&a).is_empty());
    }
}

#[test]
fn the_finding_is_emitted_as_a_graded_parsed_record() {
    let a = hive_record(vec![key("SOFTWARE\\Vendor\\Run", 9, Some(7))]);
    let out = HiveFindings::new().process(&a).expect("processed");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], FINDING_RECORD_TYPE);
    assert_eq!(out[0].metadata["grade"], "investigative_lead");
    assert_eq!(out[0].metadata["confidence"], "notable");
    assert_eq!(out[0].parent_id, Some(a.id));
}
