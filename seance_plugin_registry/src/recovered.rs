//! Keys and values recovered from a hive's unallocated space.
//!
//! `seance_hive::Hive::unallocated_cells` walks the free space for `nk`/`vk`
//! cells a deletion marked free but never overwrote (`ROADMAP` §5.9). This
//! module is the consumer it was built for: every recovered cell becomes a
//! record of its **own type** — `RecoveredRegistryKey`,
//! `RecoveredRegistryValue` — and never a `RegistryKey`/`RegistryValue` with
//! a flag, so a viewer or an export cannot fold a deleted key into the live
//! listing by forgetting to check one. The hive record carries a summary
//! with every ceiling and its number.
//!
//! # What a freed cell can and cannot say
//!
//! An `nk` cell records its own name, time, parent offset and the counts it
//! declared. Its subkey list, value list and security cell were freed with it
//! and may since have been reused, so none of them is followed: the record
//! publishes the counts as **declared** and nothing as found. A `vk` cell
//! records its name, type and size; its data is in the cell itself for four
//! bytes or fewer (read, and safe) or in another cell (read only where that
//! cell is still allocated — and then stated as possibly reused — and
//! reported unread with the reader's reason where it is not). A `vk` does
//! not name the key it belonged to, and no key is inferred for it.
//!
//! # The path is an inference
//!
//! A recovered key's path is rebuilt from its parent-offset chain through the
//! live `nk` cells and the other recovered ones. The parent slot may have been
//! reused for a different key since the deletion, so the path is labelled as
//! an inference on the record and a chain that ends on an offset holding
//! neither is published as partial with the unresolved offset.

use crate::{filetime_to_rfc3339, NkCell};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_hive::{Hive, HiveError, KeyValueData, RecoveredCell};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Ceiling on recovered records emitted from one hive, separate from the
/// walk's own [`seance_hive::MAX_UNALLOCATED_CELLS`]: that bounds how much
/// free space is examined, this bounds how many records a case takes on.
/// The same order as the live key-write timeline's cap.
pub const MAX_RECOVERED_RECORDS: usize = 50_000;

/// How deep a parent chain is followed before it is called a cycle.
const MAX_PATH_DEPTH: usize = 512;

/// One `nk` cell recovered from free space, as far as the cell itself says.
#[derive(Debug, Clone)]
pub struct RecoveredKey {
    pub name: String,
    pub bin_offset: u32,
    pub parent_offset: Option<u32>,
    pub last_written_filetime: u64,
    pub subkey_count_declared: u32,
    pub value_count_declared: u32,
}

/// Where a recovered value's bytes came from, or why they did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveredData {
    /// Four bytes or fewer, held in the freed `vk` cell's own offset field.
    Inline(Vec<u8>),
    /// The `vk`'s non-inline size field is zero: the value declares no data,
    /// and `seance_hive` answers with an empty slice **without following the
    /// offset field**. No data cell was read, so nothing can be said about
    /// one.
    DeclaredEmpty,
    /// Read from a data cell the freed `vk` points at that is **still
    /// allocated** — which means something may have reused it since.
    FromAllocatedCell(Vec<u8>),
    /// Not read, with the reader's reason.
    Unread(String),
}

/// One `vk` cell recovered from free space.
#[derive(Debug, Clone)]
pub struct RecoveredValue {
    pub name: String,
    pub bin_offset: u32,
    pub value_type: String,
    pub data_size_declared: u32,
    pub tombstoned: bool,
    pub data: RecoveredData,
}

/// A cell that opened `nk`/`vk` and would not decode past that.
#[derive(Debug, Clone)]
pub struct UndecodableCandidate {
    pub bin_offset: u32,
    pub signature: String,
    pub reason: String,
}

/// Everything one walk of a hive's free space produced, with every way it
/// could be short of the whole.
#[derive(Debug, Default)]
pub struct RecoveredCellScan {
    pub keys: Vec<RecoveredKey>,
    pub values: Vec<RecoveredValue>,
    pub undecodable: Vec<UndecodableCandidate>,
    /// The walk hit [`seance_hive::MAX_UNALLOCATED_CELLS`].
    pub examined_capped: bool,
    /// The walk stopped on a broken bin chain: free space past that point
    /// was never examined.
    pub walk_incomplete: bool,
    /// This module stopped taking records at [`MAX_RECOVERED_RECORDS`].
    pub records_capped: bool,
}

impl RecoveredCellScan {
    pub fn complete(&self) -> bool {
        !self.examined_capped && !self.walk_incomplete && !self.records_capped
    }

    fn incomplete_reason(&self) -> Option<String> {
        let mut reasons = Vec::new();
        if self.examined_capped {
            reasons.push(format!(
                "the walk stopped at its ceiling of {} cells examined; free space past that \
                 point was not looked at",
                seance_hive::MAX_UNALLOCATED_CELLS
            ));
        }
        if self.walk_incomplete {
            reasons.push(
                "the walk stopped on hive-bin data it could not make sense of; free space past \
                 that point was not looked at"
                    .to_string(),
            );
        }
        if self.records_capped {
            reasons.push(format!(
                "this module stopped at its ceiling of {MAX_RECOVERED_RECORDS} recovered records; \
                 cells found after that were not published"
            ));
        }
        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        }
    }

    /// The summary stamped on the hive record.
    pub fn summary(&self) -> Value {
        json!({
            "keys": self.keys.len(),
            "values": self.values.len(),
            "undecodable": self.undecodable.len(),
            "undecodable_cells": self.undecodable.iter().map(|c| json!({
                "bin_offset": c.bin_offset,
                "signature": c.signature,
                "reason": c.reason,
            })).collect::<Vec<_>>(),
            "examined_cap": seance_hive::MAX_UNALLOCATED_CELLS,
            "examined_capped": self.examined_capped,
            "walk_incomplete": self.walk_incomplete,
            "records_cap": MAX_RECOVERED_RECORDS,
            "records_capped": self.records_capped,
            "complete": self.complete(),
            "incomplete_reason": self.incomplete_reason(),
            "basis": "cells in the hive's unallocated space whose first bytes are an nk or vk \
                      signature, decoded with the same field parsing as the live tree. A \
                      recovered cell is evidence that such a key or value existed and was \
                      deleted or moved; its absence from this list is not evidence that none \
                      was, because a freed cell is reused on the next write.",
        })
    }
}

/// Walk the hive's free space and collect what it holds, bounded.
pub fn recover_unallocated_cells(hive: &Hive<'_>) -> RecoveredCellScan {
    let mut scan = RecoveredCellScan::default();
    let mut walk = hive.unallocated_cells();
    for cell in walk.by_ref() {
        if scan.keys.len() + scan.values.len() + scan.undecodable.len() >= MAX_RECOVERED_RECORDS {
            scan.records_capped = true;
            break;
        }
        match cell.cell {
            RecoveredCell::Key(node) => {
                let name = match node.name() {
                    Ok(n) => n.to_string_lossy(),
                    Err(e) => {
                        scan.undecodable.push(UndecodableCandidate {
                            bin_offset: cell.bin_offset,
                            signature: "nk".into(),
                            reason: format!("name: {e}"),
                        });
                        continue;
                    }
                };
                scan.keys.push(RecoveredKey {
                    name,
                    bin_offset: cell.bin_offset,
                    parent_offset: node.parent_offset(),
                    last_written_filetime: node.last_written_filetime(),
                    subkey_count_declared: node.subkey_count(),
                    value_count_declared: node.value_count(),
                });
            }
            RecoveredCell::Value(value) => {
                let name = match value.name() {
                    Ok(n) => n.to_string_lossy(),
                    Err(e) => {
                        scan.undecodable.push(UndecodableCandidate {
                            bin_offset: cell.bin_offset,
                            signature: "vk".into(),
                            reason: format!("name: {e}"),
                        });
                        continue;
                    }
                };
                let value_type = match value.data_type() {
                    Ok(dt) => format!("{dt:?}"),
                    Err(_) => "Unknown".to_string(),
                };
                let data = match value.data() {
                    Ok(KeyValueData::Inline(bytes, len)) => {
                        RecoveredData::Inline(bytes[..len].to_vec())
                    }
                    // `KeyValue::data` returns this before it reads any cell
                    // when the size field is zero; the offset field was not
                    // followed, so `FromAllocatedCell` would be a claim
                    // about a cell nobody looked at.
                    Ok(_) if value.data_size() == 0 => RecoveredData::DeclaredEmpty,
                    Ok(other) => match other.into_vec() {
                        Ok(bytes) => RecoveredData::FromAllocatedCell(bytes),
                        Err(e) => RecoveredData::Unread(e.to_string()),
                    },
                    Err(e) => RecoveredData::Unread(unread_reason(&e)),
                };
                scan.values.push(RecoveredValue {
                    name,
                    bin_offset: cell.bin_offset,
                    value_type,
                    data_size_declared: value.data_size(),
                    tombstoned: value.is_tombstoned(),
                    data,
                });
            }
            RecoveredCell::Undecodable { signature, error } => {
                scan.undecodable.push(UndecodableCandidate {
                    bin_offset: cell.bin_offset,
                    signature: String::from_utf8_lossy(&signature).into_owned(),
                    reason: error.to_string(),
                });
            }
        }
    }
    scan.examined_capped = walk.is_capped();
    scan.walk_incomplete = walk.is_incomplete();
    scan
}

/// The reader's refusal, in the sentence the record carries. A data cell
/// that is itself free is the ordinary case for a deleted value and is
/// named as such rather than as an error.
fn unread_reason(e: &HiveError) -> String {
    match e {
        HiveError::CellNotAllocated { offset } => format!(
            "the data cell at bin offset {offset:#x} is not allocated: it was freed with the \
             value and its bytes are not read, because a freed cell's contents cannot be \
             attributed to this value"
        ),
        other => other.to_string(),
    }
}

/// A recovered key's path: followed through the live cells and the other
/// recovered keys. `complete` is false when the chain ended on an offset
/// that resolves to neither, and `unresolved` says which.
struct InferredPath {
    path: String,
    complete: bool,
    unresolved: Option<u32>,
}

fn infer_path(
    key: &RecoveredKey,
    live: &HashMap<u32, NkCell>,
    recovered: &HashMap<u32, &RecoveredKey>,
) -> InferredPath {
    let mut parts: Vec<&str> = vec![if key.name.is_empty() {
        "(root)"
    } else {
        &key.name
    }];
    let mut seen: HashSet<u32> = HashSet::new();
    seen.insert(key.bin_offset);
    let mut parent = key.parent_offset;
    let mut complete = true;
    let mut unresolved = None;
    for _ in 0..MAX_PATH_DEPTH {
        let Some(offset) = parent else {
            break;
        };
        if !seen.insert(offset) {
            complete = false;
            unresolved = Some(offset);
            break;
        }
        if let Some(live_parent) = live.get(&offset) {
            if !live_parent.name.is_empty() {
                parts.push(&live_parent.name);
            }
            parent = (!live_parent.is_root && live_parent.parent_rel != u32::MAX)
                .then_some(live_parent.parent_rel);
        } else if let Some(recovered_parent) = recovered.get(&offset) {
            if !recovered_parent.name.is_empty() {
                parts.push(&recovered_parent.name);
            }
            parent = recovered_parent.parent_offset;
        } else {
            complete = false;
            unresolved = Some(offset);
            break;
        }
    }
    parts.reverse();
    InferredPath {
        path: parts.join("\\"),
        complete,
        unresolved,
    }
}

const PATH_BASIS: &str = "rebuilt from the freed nk cell's parent-offset chain through the \
    hive's live nk cells and the other recovered ones. The parent slot may have been reused \
    for a different key since this one was deleted, so the path is an inference from offsets \
    and not a fact the cell records; the cell records only its own name and its parent's offset.";

const KEY_RECOVERY_NOTE: &str = "an nk cell in the hive's unallocated space: marked free by a \
    deletion (or a move) and not yet overwritten. It is not in the live tree. Its subkey list, \
    value list and security cell were freed with it and may have been reused, so none is \
    followed: the counts below are what the cell declares, not what was found.";

const LIVE_NAMESAKE_NOTE: &str = "the live tree holds a key of this name under the same parent, \
    at another offset. This freed cell is then a previous version of that key — Windows writes \
    a key node afresh when it grows, or a transaction rolled one back — or a namesake that was \
    removed; the cell does not say which, and it is not evidence that the key was deleted.";

/// How a recovered default value (a `vk` with no name) is named for display —
/// the convention `regedit` uses. Its `value_name` stays empty.
const DEFAULT_VALUE_DISPLAY_NAME: &str = "(Default)";

const VALUE_ASSOCIATION_NOTE: &str = "a vk cell does not record the key it belonged to, and the \
    key's value list that once named it was freed with it, so no key is inferred for this value.";

/// Turn the scan into records: one `ParsedRecord` per recovered key and
/// value, and one `TimelineEvent` of its own kind per key with a readable
/// time. `live` is the map of allocated nk cells the key-write scan built,
/// used only to rebuild paths.
pub(crate) fn emit(
    scan: &RecoveredCellScan,
    live: &HashMap<u32, NkCell>,
    hive_name: &str,
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    replay: &Value,
) -> Vec<Artifact> {
    let recovered_by_offset: HashMap<u32, &RecoveredKey> =
        scan.keys.iter().map(|k| (k.bin_offset, k)).collect();
    // Every live key by (parent offset, lower-cased name), so a recovered
    // key can be checked for a live namesake without rebuilding every path.
    let live_children: HashSet<(u32, String)> = if scan.keys.is_empty() {
        HashSet::new()
    } else {
        live.values()
            .map(|cell| (cell.parent_rel, cell.name.to_lowercase()))
            .collect()
    };
    let mut out = Vec::with_capacity(scan.keys.len() * 2 + scan.values.len());

    for key in &scan.keys {
        let inferred = infer_path(key, live, &recovered_by_offset);
        let live_namesake = key
            .parent_offset
            .is_some_and(|p| live_children.contains(&(p, key.name.to_lowercase())));
        let last_written = filetime_to_rfc3339(key.last_written_filetime);
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("RecoveredRegistryKey"));
        m.insert(
            "name".into(),
            json!(format!("{} (recovered)", inferred.path)),
        );
        m.insert("hive".into(), json!(hive_name));
        m.insert("key_name".into(), json!(key.name));
        m.insert("key_path".into(), json!(inferred.path));
        m.insert("key_path_is_inference".into(), json!(true));
        m.insert("key_path_complete".into(), json!(inferred.complete));
        if let Some(offset) = inferred.unresolved {
            m.insert("key_path_parent_offset_unresolved".into(), json!(offset));
        }
        m.insert("key_path_basis".into(), json!(PATH_BASIS));
        m.insert("bin_offset".into(), json!(key.bin_offset));
        m.insert("parent_offset".into(), json!(key.parent_offset));
        m.insert("last_written".into(), json!(last_written));
        m.insert(
            "last_written_filetime".into(),
            json!(key.last_written_filetime),
        );
        m.insert(
            "subkey_count_declared".into(),
            json!(key.subkey_count_declared),
        );
        m.insert(
            "value_count_declared".into(),
            json!(key.value_count_declared),
        );
        m.insert(
            "live_key_with_same_name_under_parent".into(),
            json!(live_namesake),
        );
        if live_namesake {
            m.insert("live_namesake_note".into(), json!(LIVE_NAMESAKE_NOTE));
        }
        m.insert("evidence_state".into(), json!("recovered"));
        m.insert("recovered_from".into(), json!("unallocated hive cell"));
        m.insert("recovery_note".into(), json!(KEY_RECOVERY_NOTE));
        m.insert("replay".into(), replay.clone());
        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
                .with_parent(parent_id),
        );

        if let Some(when) = last_written {
            out.push(
                Artifact::new(
                    case_id,
                    ArtifactType::TimelineEvent,
                    None,
                    json!({
                        "type": "TimelineEvent",
                        "timestamp": when,
                        "timestamp_desc": "Recovered Registry Key Last Written",
                        "source_module": "plugin.windows.registry_parser",
                        "short_desc": format!(
                            "Recovered (deleted) registry key last written: {}",
                            inferred.path
                        ),
                        "key_path": inferred.path,
                        "key_path_is_inference": true,
                        "bin_offset": key.bin_offset,
                        "evidence_state": "recovered",
                        "source": "Registry",
                        "source_long": format!("Recovered registry key ({hive_name})"),
                        "replay": replay.clone(),
                    }),
                )
                .with_parent(parent_id),
            );
        }
    }

    // The recovered values' own share of the per-hive cap on published bytes.
    let mut value_bytes = crate::ValueBytesBudget::with_limit(crate::MAX_VALUE_BYTES_PER_HIVE);
    for value in &scan.values {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("RecoveredRegistryValue"));
        // A value with no name is the key's default value. `value_name` stays
        // the empty string the cell holds; only the display name says which
        // value it is, where it rendered as " (recovered)" (HUNT-167).
        let display_name = if value.name.is_empty() {
            DEFAULT_VALUE_DISPLAY_NAME
        } else {
            value.name.as_str()
        };
        m.insert("name".into(), json!(format!("{display_name} (recovered)")));
        m.insert("hive".into(), json!(hive_name));
        m.insert("value_name".into(), json!(value.name));
        m.insert("value_type".into(), json!(value.value_type));
        m.insert("key_path".into(), Value::Null);
        m.insert("key_association_note".into(), json!(VALUE_ASSOCIATION_NOTE));
        m.insert("bin_offset".into(), json!(value.bin_offset));
        m.insert(
            "raw_data_size_declared".into(),
            json!(value.data_size_declared),
        );
        m.insert("tombstoned".into(), json!(value.tombstoned));
        match &value.data {
            RecoveredData::Inline(bytes) | RecoveredData::FromAllocatedCell(bytes) => {
                m.insert("data_read".into(), json!(true));
                crate::publish_value_data(&mut m, &value.value_type, bytes, &mut value_bytes);
                m.insert("raw_data_size".into(), json!(bytes.len()));
                let basis = if matches!(value.data, RecoveredData::Inline(_)) {
                    "inline in the freed vk cell itself"
                } else {
                    "an allocated data cell the freed vk points at. The cell is in use now, \
                     and may have been reused by another value since this one was deleted, so \
                     these bytes are what the cell holds today and not necessarily what this \
                     value held."
                };
                m.insert("data_basis".into(), json!(basis));
            }
            RecoveredData::DeclaredEmpty => {
                m.insert("data_read".into(), json!(true));
                m.insert("value_data".into(), json!(""));
                m.insert("raw_data_size".into(), json!(0));
                m.insert(
                    "data_basis".into(),
                    json!(
                        "the freed vk's data-size field is zero, so the value declares no data \
                         and no data cell was read: the offset field was not followed, and \
                         nothing is known about whatever cell it names."
                    ),
                );
            }
            RecoveredData::Unread(reason) => {
                m.insert("data_read".into(), json!(false));
                m.insert("value_data".into(), Value::Null);
                m.insert("data_unread_reason".into(), json!(reason));
            }
        }
        m.insert("evidence_state".into(), json!("recovered"));
        m.insert("recovered_from".into(), json!("unallocated hive cell"));
        m.insert("replay".into(), replay.clone());
        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
                .with_parent(parent_id),
        );
    }
    out
}
