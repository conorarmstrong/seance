//! Registry key security: who could change a key.
//!
//! # What an examiner asks this for
//!
//! "Why did this Run key survive?" and "who could have written it?" are ACL
//! questions, and a hive's `sk` cells are the only record of the answer. This
//! module turns those cells into two things: a per-key statement of the key's
//! security state, and the hive's distinct descriptor population.
//!
//! # Why the population is separate from the keys
//!
//! Descriptors are shared. On `reference/plaso/test_data/SOFTWARE`, 117,488
//! keys resolve to 289 descriptors, and one of those descriptors is named by
//! 42,002 keys. Writing a decoded ACL onto every key would repeat one answer
//! 42,002 times and still not say the thing that matters — that these 42,002
//! keys share one ACL, and *that* one over there is carried by a single key.
//!
//! A descriptor carried by exactly one key is what a widened ACL looks like:
//! everything around it inherited the same security, and this one did not.
//! That is why `unique_to_one_key` and `differs_from_parent` are recorded.
//!
//! # What this module will not do
//!
//! **It computes no effective access.** "Who could actually write this key"
//! needs group membership that the hive alone does not hold, plus deny-ordering
//! and the kernel's generic mapping. Nothing here answers it.
//!
//! **It raises no finding.** A "widened ACL" lead is a scored judgement, and a
//! scored judgement over this data belongs to something that has measured its
//! own false-positive rate. `HUNT-122` is what that costs when it is skipped:
//! one classifier, 788 false leads on a single image.

use seance_core::io::IncompleteReason;
use seance_core::secdesc::wellknown::ObjectKind;
use seance_core::secdesc::{parse_security_descriptor_on, AclPresence, SecurityDescriptor};
use seance_hive::{Hive, KeyNode};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// What a key records about its own security.
///
/// Three states, not two. A key that records **no** descriptor and a key whose
/// descriptor **would not read** are different facts, and an examiner reading
/// "no security shown" is entitled to know which one they have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySecurity {
    /// The key names a descriptor, and it read. The offset is the sharing
    /// identity: two keys with the same offset have the same ACL.
    Recorded { cell_offset: u32 },
    /// The key names no descriptor at all.
    ///
    /// Not one of the 334,111 key nodes in the twelve corpus hives does this,
    /// so on real evidence it is itself worth remarking on.
    NoneRecorded,
    /// The key names a descriptor that could not be read.
    Unreadable { reason: String },
}

impl KeySecurity {
    /// Read a key's security state without decoding the descriptor.
    pub fn of(key_node: &KeyNode<'_>) -> Self {
        match key_node.security() {
            None => Self::NoneRecorded,
            Some(Ok(cell)) => Self::Recorded {
                cell_offset: cell.cell_offset(),
            },
            Some(Err(e)) => Self::Unreadable {
                reason: e.to_string(),
            },
        }
    }

    /// The word this state is reported by, on the key record and on screen.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Recorded { .. } => "recorded",
            Self::NoneRecorded => "none_recorded",
            Self::Unreadable { .. } => "unreadable",
        }
    }
}

/// Write a key's security state onto its record.
///
/// The offset is written as well as the state, because it is what makes "these
/// keys share an ACL" expressible at all — and because it is the join back to
/// the descriptor population, which holds the decoded ACL exactly once.
pub fn stamp_key_security(key_data: &mut Value, state: &KeySecurity) {
    let map = match key_data.as_object_mut() {
        Some(m) => m,
        None => return,
    };
    map.insert("security".to_string(), json!(state.as_str()));
    match state {
        KeySecurity::Recorded { cell_offset } => {
            map.insert("security_descriptor_cell".to_string(), json!(cell_offset));
        }
        KeySecurity::NoneRecorded => {
            map.insert(
                "security_note".to_string(),
                json!(
                    "This key records no security descriptor. That is not the same as a key \
                       anyone may write: the absence means the hive holds no ACL for it, and \
                       what governed access is not in this evidence."
                ),
            );
        }
        KeySecurity::Unreadable { reason } => {
            // A scoped incompleteness, the way `subkeys_incomplete` is scoped:
            // this key's ACL is missing from the inventory, and nothing else
            // about the key is in doubt.
            map.insert("security_incomplete".to_string(), json!(true));
            map.insert(
                "security_incomplete_reason".to_string(),
                json!(IncompleteReason::UnresolvedStructure.as_str()),
            );
            map.insert("security_incomplete_detail".to_string(), json!(reason));
        }
    }
}

/// One distinct descriptor, with what the hive says about it and what the walk
/// found.
#[derive(Clone, Debug)]
pub struct DescriptorEntry {
    /// The cell, which is the descriptor's identity.
    pub cell_offset: u32,
    /// What the hive's own cell says: how many keys share this descriptor.
    pub reference_count: u32,
    /// How many keys the walk actually saw naming it.
    pub keys_referencing: usize,
    /// The decoded descriptor, or `None` when the bytes would not decode.
    pub descriptor: Option<SecurityDescriptor>,
    /// Why the descriptor did not decode.
    pub decode_error: Option<String>,
}

impl DescriptorEntry {
    /// A descriptor carried by exactly one key.
    ///
    /// This is the shape a widened ACL takes: the keys around it inherited one
    /// descriptor and this one did not. It is an **observation**, not a finding
    /// — most singletons on a real hive are ordinary (`SOFTWARE` has many), and
    /// saying otherwise without a measured false-positive rate is `HUNT-122`.
    pub fn unique_to_one_key(&self) -> bool {
        self.keys_referencing == 1
    }

    /// Whether the hive's own reference count agrees with the walk.
    ///
    /// In all twelve corpus hives it agrees exactly. A disagreement is a fact
    /// about the hive — an undecremented delete, a damaged cell — and is
    /// reported rather than reconciled.
    pub fn count_agrees_with_walk(&self) -> bool {
        self.reference_count as usize == self.keys_referencing
    }

    /// The record this entry becomes.
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("cell_offset".into(), json!(self.cell_offset));
        m.insert("reference_count".into(), json!(self.reference_count));
        m.insert("keys_referencing".into(), json!(self.keys_referencing));
        m.insert("unique_to_one_key".into(), json!(self.unique_to_one_key()));
        if !self.count_agrees_with_walk() {
            m.insert("reference_count_disagrees_with_walk".into(), json!(true));
            m.insert(
                "reference_count_disagreement".into(),
                json!(format!(
                    "The hive's cell declares {} reference(s) to this descriptor; the walk \
                     found {}. The declared count is transcribed as it was found, not \
                     corrected, because which is right is itself evidence.",
                    self.reference_count, self.keys_referencing
                )),
            );
        }
        match (&self.descriptor, &self.decode_error) {
            (Some(d), _) => {
                m.insert(
                    "owner".into(),
                    json!(d.owner.as_ref().map(|s| s.to_string())),
                );
                m.insert("owner_name".into(), json!(d.owner_label()));
                m.insert(
                    "group".into(),
                    json!(d.group.as_ref().map(|s| s.to_string())),
                );
                m.insert("control".into(), json!(d.control));
                m.insert("dacl_state".into(), json!(acl_state_word(&d.dacl)));
                m.insert("sacl_state".into(), json!(acl_state_word(&d.sacl)));
                m.insert("permission_summary".into(), json!(d.permission_summary()));
                // A descriptor that decoded only partly must never read as a
                // complete permission picture.
                if d.partial {
                    m.insert("security_incomplete".into(), json!(true));
                    m.insert(
                        "security_incomplete_reason".into(),
                        json!(IncompleteReason::UnresolvedStructure.as_str()),
                    );
                }
            }
            (None, Some(why)) => {
                m.insert("security_incomplete".into(), json!(true));
                m.insert(
                    "security_incomplete_reason".into(),
                    json!(IncompleteReason::UnresolvedStructure.as_str()),
                );
                m.insert("security_incomplete_detail".into(), json!(why));
            }
            (None, None) => {}
        }
        Value::Object(m)
    }
}

/// The four DACL states, in the word each is reported by.
///
/// The distinction this exists for: **no DACL means everyone has full access**
/// and **an empty DACL means nobody does**. Rendering both as "no permissions
/// shown" inverts the answer to the question being asked.
fn acl_state_word(presence: &AclPresence) -> &'static str {
    match presence {
        AclPresence::Absent => "absent",
        AclPresence::Null => "null",
        AclPresence::Present(_) => "present",
        AclPresence::Unreadable { .. } => "unreadable",
    }
}

/// The hive's distinct descriptor population, and what the walk could not
/// assess about it.
#[derive(Clone, Debug, Default)]
pub struct SecurityInventory {
    /// Keys whose descriptor would not read.
    pub unreadable_keys: u64,
    /// Keys that record no descriptor at all.
    pub keys_without_security: u64,
    /// Why the descriptor population is short, if it is.
    pub population_incomplete: Option<String>,
    /// Cell offset → how many keys the walk saw naming it.
    references: BTreeMap<u32, usize>,
}

impl SecurityInventory {
    /// Record one key's security state as the walk passes it.
    pub fn observe(&mut self, state: &KeySecurity) {
        match state {
            KeySecurity::Recorded { cell_offset } => {
                *self.references.entry(*cell_offset).or_insert(0) += 1;
            }
            KeySecurity::NoneRecorded => self.keys_without_security += 1,
            KeySecurity::Unreadable { .. } => self.unreadable_keys += 1,
        }
    }

    /// Decode the distinct descriptors, walking the hive's `sk` ring.
    ///
    /// The ring is the enumeration, not the keys: 289 reads rather than 117,488
    /// on `SOFTWARE`. A ring member the walk never saw a key name is still
    /// listed, with `keys_referencing: 0` — it is a descriptor the hive holds,
    /// and its absence from the walk is a fact about the walk.
    pub fn resolve(&mut self, hive: &Hive<'_>) -> Vec<DescriptorEntry> {
        let ring = match hive.security_descriptors() {
            Ok(ring) => ring,
            Err(e) => {
                self.population_incomplete = Some(format!(
                    "The hive's security ring could not be walked ({e}), so the descriptors \
                     below are only those the key walk reached and the distinct population \
                     is not known."
                ));
                return Vec::new();
            }
        };
        if let Some(why) = ring.incomplete_reason() {
            self.population_incomplete = Some(format!(
                "{why}, so this is not necessarily every descriptor the hive holds."
            ));
        }
        ring.iter()
            .map(|cell| {
                let bytes = cell.descriptor();
                let (descriptor, decode_error) =
                    match parse_security_descriptor_on(ObjectKind::RegistryKey, bytes) {
                        Ok(d) => (Some(d), None),
                        Err(e) => (None, Some(e.to_string())),
                    };
                DescriptorEntry {
                    cell_offset: cell.cell_offset(),
                    reference_count: cell.reference_count(),
                    keys_referencing: self
                        .references
                        .get(&cell.cell_offset())
                        .copied()
                        .unwrap_or(0),
                    descriptor,
                    decode_error,
                }
            })
            .collect()
    }

    /// The hive-record summary of what security could and could not be read.
    ///
    /// Always emitted, including when nothing was wrong, because "the security
    /// of every key was read" is itself the answer to a question an examiner
    /// asks and must not have to be inferred from the absence of a warning.
    pub fn to_json(&self, descriptors: &[DescriptorEntry]) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("distinct_descriptors".into(), json!(descriptors.len()));
        m.insert(
            "keys_with_security".into(),
            json!(self.references.values().sum::<usize>()),
        );
        m.insert(
            "keys_without_security".into(),
            json!(self.keys_without_security),
        );
        m.insert(
            "keys_with_unreadable_security".into(),
            json!(self.unreadable_keys),
        );
        let complete = self.unreadable_keys == 0 && self.population_incomplete.is_none();
        m.insert("security_complete".into(), json!(complete));
        if !complete {
            m.insert("security_incomplete".into(), json!(true));
            m.insert(
                "security_incomplete_reason".into(),
                json!(IncompleteReason::UnresolvedStructure.as_str()),
            );
            let mut detail = Vec::new();
            if self.unreadable_keys > 0 {
                detail.push(format!(
                    "{} key(s) name a security descriptor that could not be read, so their \
                     ACLs are absent from this inventory but not from the hive.",
                    self.unreadable_keys
                ));
            }
            if let Some(why) = &self.population_incomplete {
                detail.push(why.clone());
            }
            m.insert("security_incomplete_detail".into(), json!(detail.join(" ")));
        }
        Value::Object(m)
    }
}
