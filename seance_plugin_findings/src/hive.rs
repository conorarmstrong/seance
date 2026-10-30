//! A registry hive that disagrees with itself about how many subkeys a key has
//! (§2.2, detection 8).
//!
//! A key node records a subkey count in its own fixed fields, and separately
//! points at an index listing its subkeys. `seance_hive` reads both and refuses
//! to reconcile them: `SubKeyNodes::listed_len` is what the index names,
//! `KeyNode::subkey_count` is what the key claims, and a reader that silently
//! trusted one over the other would present a key's contents as settled while
//! the hive itself disagreed about them.
//!
//! # Which direction the disagreement runs matters
//!
//! **Declared more than listed.** The usual shape, and the interesting one. A
//! key that says it has nine children whose index names seven has lost two —
//! to damage, or because two were deleted and the parent's count was never
//! decremented. The second case is a lead: a deleted key's name may still be
//! recoverable from the hive's free cells, and the count is the only evidence
//! it ever existed.
//!
//! **Listed more than declared.** Rarer, and it means the count was not
//! updated for an index that grew. Reported the same way, because the reason a
//! reader cares is identical: the hive's two accounts of this key differ, and
//! the enumeration is one of them.
//!
//! # One finding per hive, not per key
//!
//! Damage is not distributed evenly. A hive with a torn index root produces
//! hundreds of disagreeing keys from one cause, and a triage list with three
//! hundred rows saying the same thing is worse than no list. So the finding is
//! raised once per hive, names the keys up to a cap, and always states the full
//! count so the cap cannot be mistaken for the total.

use crate::prelude::*;

/// The record type the registry plugin writes for a hive.
const HIVE_RECORD_TYPE: &str = "RegistryHive";

/// The module id, written once so every finding cites the same source.
const HIVE_MODULE_ID: &str = "plugin.findings.hive";

/// How many disagreeing keys are named in the evidence. The full count is
/// always stated, so this bounds the row without hiding the scale.
const MAX_NAMED_KEYS: usize = 10;

/// Raises a lead from a `RegistryHive` record whose keys disagree with their
/// own indexes.
#[derive(Debug, Default)]
pub struct HiveFindings;

impl HiveFindings {
    pub fn new() -> Self {
        Self
    }

    /// The findings for one hive record, or none.
    pub fn findings_for(&self, artifact: &Artifact) -> Vec<Finding> {
        if meta_str(artifact, "type").as_deref() != Some(HIVE_RECORD_TYPE) {
            return Vec::new();
        }
        let Some(keys) = artifact.metadata.get("all_keys").and_then(|v| v.as_array()) else {
            return Vec::new();
        };

        // (path, declared, listed) for every key whose two accounts differ.
        let mut disagreeing: Vec<(String, u64, u64)> = Vec::new();
        for key in keys {
            if key
                .get("subkey_count_disagrees_with_index")
                .and_then(|v| v.as_bool())
                != Some(true)
            {
                continue;
            }
            let Some(declared) = key.get("subkey_count").and_then(|v| v.as_u64()) else {
                continue;
            };
            let Some(listed) = key.get("subkeys_listed").and_then(|v| v.as_u64()) else {
                continue;
            };
            let path = key
                .get("key_path")
                .and_then(|v| v.as_str())
                .unwrap_or("(an unnamed key)")
                .to_string();
            disagreeing.push((path, declared, listed));
        }
        if disagreeing.is_empty() {
            return Vec::new();
        }

        // The keys that lost children first: those are the ones where a
        // deleted key's name may still be in the hive's free cells.
        disagreeing.sort_by_key(|(path, declared, listed)| {
            (
                // `declared > listed` sorts first.
                listed >= declared,
                // then by how much was lost, most first
                std::cmp::Reverse(declared.abs_diff(*listed)),
                path.clone(),
            )
        });

        let hive = meta_str(artifact, "hive_type")
            .or_else(|| meta_str(artifact, "name"))
            .unwrap_or_else(|| "a registry hive".to_string());
        let total = disagreeing.len();
        let missing: usize = disagreeing.iter().filter(|(_, d, l)| d > l).count();

        let mut evidence = vec![
            EvidenceItem::new("hive", hive.clone()),
            EvidenceItem::new("keys_disagreeing", total.to_string()),
            EvidenceItem::new(
                "keys_declaring_more_than_the_index_names",
                missing.to_string(),
            ),
        ];
        if let Some(n) = artifact.metadata.get("total_keys").and_then(|v| v.as_u64()) {
            evidence.push(EvidenceItem::new("keys_walked_in_this_hive", n.to_string()));
        }
        for (path, declared, listed) in disagreeing.iter().take(MAX_NAMED_KEYS) {
            evidence.push(EvidenceItem::new(
                path.clone(),
                format!("declares {declared}, index names {listed}"),
            ));
        }
        if total > MAX_NAMED_KEYS {
            evidence.push(EvidenceItem::new(
                "keys not named above",
                format!(
                    "{} further key(s) disagree; the hive record's `all_keys` carries every \
                     one, each stamped `subkey_count_disagrees_with_index`",
                    total - MAX_NAMED_KEYS
                ),
            ));
        }
        // A hive that also lost whole sublists is damaged in a second, worse
        // way, and the two must not be conflated: the count disagreement is a
        // discrepancy, an unreadable sublist is a hole.
        let torn_indexes = keys
            .iter()
            .filter(|k| k.get("subkeys_incomplete").and_then(|v| v.as_bool()) == Some(true))
            .count();
        if torn_indexes > 0 {
            evidence.push(EvidenceItem::new(
                "keys whose subkey index would not read",
                format!(
                    "{torn_indexes}; those keys are short for a different reason — part of \
                     their index could not be read at all — and are recorded separately as \
                     incomplete"
                ),
            ));
        }

        // Whether the logs were replayed is the hive record's to say, not this
        // module's to assume (HUNT-201): the registry plugin replays them
        // before it parses and stamps the outcome on the record.
        for field in ["logs_replayed", "hive_dirty", "replay_reason"] {
            if let Some(v) = artifact.metadata.get(field).filter(|v| !v.is_null()) {
                let value = v.as_str().map(str::to_string).unwrap_or(v.to_string());
                evidence.push(EvidenceItem::new(field, value));
            }
        }

        vec![Finding {
            kind: "hive_subkey_count_discrepancy".to_string(),
            title: if total == 1 {
                format!(
                    "A key in {hive} declares a different number of subkeys than its index names"
                )
            } else {
                format!("{total} keys in {hive} declare a different number of subkeys than their indexes name")
            },
            subject_artifact: subject_of(artifact),
            confidence: Confidence::Notable,
            observation: format!(
                "In {hive}, {total} key(s) record a subkey count in their own fields that does \
                 not equal the number of subkeys their index names; {missing} of them declare \
                 more than the index names. The enumeration in this hive's record is the \
                 index.",
            ),
            evidence,
            inference: Some(
                "A key that counts more children than its index names has lost them. Deleting \
                 a key unlinks it from its parent's index, and a count the delete did not \
                 decrement is the surviving evidence that it was there — the key's name and \
                 values may still be in the hive's unallocated cells."
                    .to_string(),
            ),
            qualification: format!(
                "This does not establish that anything was deleted, or that the hive was \
                 tampered with. The ordinary cause is a hive that was not cleanly flushed: a \
                 hive copied from a running system, or recovered from a shadow copy, has its \
                 most recent writes in the transaction logs (`.LOG1` / `.LOG2`) rather than in \
                 the file, and replaying those is what reconciles the two counts. {} \
                 Corruption from a bad shutdown or a failing disk produces the same \
                 discrepancy. What the finding establishes is narrow and worth exactly its \
                 narrowness: the hive as read gives two different answers for these keys, and \
                 every subkey listing taken from it is the index's answer.",
                replay_sentence(artifact)
            ),
            // A hive record covers a whole file; there is no one offset, and
            // offset 0 is a real place on the device.
            device_offset: None,
            source_module: HIVE_MODULE_ID.to_string(),
        }]
    }
}

/// The sentence saying what was done with the transaction logs, read from the
/// replay provenance the registry plugin stamps on the hive record
/// (`logs_replayed`, `hive_dirty`, `replay_reason`, `log_entries_applied`).
///
/// It used to say "Séance did not replay them" unconditionally, while the
/// plugin had replayed them before parsing — false in fact on every dirty hive
/// whose logs were reachable (HUNT-201). A record without the fields says
/// nothing either way, rather than guessing.
fn replay_sentence(artifact: &Artifact) -> String {
    let md = &artifact.metadata;
    let replayed = md.get("logs_replayed").and_then(|v| v.as_bool());
    let dirty = md.get("hive_dirty").and_then(|v| v.as_bool());
    let reason = md
        .get("replay_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("not stated");
    match (replayed, dirty) {
        (Some(true), _) => {
            let entries = md
                .get("log_entries_applied")
                .and_then(|v| v.as_u64())
                .map(|n| format!(" ({n} log entries applied)"))
                .unwrap_or_default();
            if reason == "recovered" {
                format!(
                    "Séance replayed the transaction logs before reading this hive{entries}, \
                     and the counts above were read from the replayed hive, so the \
                     discrepancy survives the replay: the logs did not reconcile it."
                )
            } else {
                format!(
                    "Séance replayed the transaction logs before reading this hive{entries}, \
                     but the replay stopped early (`{reason}`), so writes the logs hold past \
                     that point were not applied and may be what would reconcile the counts."
                )
            }
        }
        (Some(false), Some(true)) => format!(
            "The hive is dirty and Séance did not replay them (`{reason}`), so this may be \
             the cause here."
        ),
        (Some(false), Some(false)) if reason == "clean" => {
            "This copy's header records a clean flush (`clean`): it had no pending log writes \
             to replay, so unflushed writes are not the explanation for this copy."
                .to_string()
        }
        (Some(false), _) => format!(
            "Séance did not replay them (`{reason}`), so whether that cause applies here is \
             not established."
        ),
        _ => "The hive record does not say whether the transaction logs were replayed, so \
              whether that cause applies here is not established."
            .to_string(),
    }
}

impl ForensicsModule for HiveFindings {
    fn id(&self) -> &str {
        HIVE_MODULE_ID
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::ParsedRecord]
    }

    /// Reads no bytes at all, only the metadata the registry plugin wrote.
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        emit(artifact, self.findings_for(artifact))
    }
}
