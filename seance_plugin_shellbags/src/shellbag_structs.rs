use seance_core::artifact::{Artifact, ArtifactType};
// One reader for the shell item, shared with the registry MRUs and whatever
// else meets a PIDL. `ROADMAP` §5.16.
use seance_hive::KeyNode;
use seance_shell_item::{parse_shell_item, shell_item_mtime, shell_item_times, FAT_TIME_NOTE};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

/// BagMRU nesting mirrors folder depth. Cap recursion to defend against a
/// hostile or corrupt hive whose subkey list forms a cycle: the walk follows
/// on-disk cell offsets and does not itself detect cycles, so an unbounded walk
/// could recurse until the stack overflows.
pub(crate) const MAX_BAGMRU_DEPTH: usize = 256;

pub struct ShellBagParser {
    case_id: Uuid,
    parent_id: Uuid,
}

impl ShellBagParser {
    pub fn new(case_id: Uuid, parent_id: Uuid) -> Self {
        Self { case_id, parent_id }
    }

    pub fn parse_bag_mru(&self, node: &KeyNode<'_>, parent_path: &str) -> Vec<Artifact> {
        self.parse_bag_mru_depth(node, parent_path, 0)
    }

    fn parse_bag_mru_depth(
        &self,
        node: &KeyNode<'_>,
        parent_path: &str,
        depth: usize,
    ) -> Vec<Artifact> {
        if let Some(stop) = self.depth_guard(parent_path, depth) {
            return stop;
        }

        let mut artifacts = Vec::new();

        // 1. Get all values in this key
        let mut slots: HashMap<String, Vec<u8>> = HashMap::new();

        if let Some(Ok(vals)) = node.values() {
            for val in vals.flatten() {
                let name_string = val.name().map(|n| n.to_string()).unwrap_or_default();
                if name_string.parse::<u32>().is_ok() {
                    if let Ok(data) = val.data() {
                        if let Ok(v) = data.into_vec() {
                            slots.insert(name_string, v);
                        }
                    }
                }
            }
        }

        // 2. Iterate over subkeys
        if let Some(Ok(keys)) = node.subkeys() {
            for subkey in keys.flatten() {
                let slot_name = subkey.name().map(|n| n.to_string()).unwrap_or_default();

                if let Some(shell_item_data) = slots.get(&slot_name) {
                    let folder_name = parse_shell_item(shell_item_data);
                    let full_path = format!("{}\\{}", parent_path, folder_name);

                    let artifact = Artifact::new(
                        self.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        with_key_last_written(
                            shellbag_entry_metadata(
                                &full_path,
                                &folder_name,
                                &slot_name,
                                shell_item_data,
                            ),
                            subkey.last_written_filetime(),
                        ),
                    )
                    .with_parent(self.parent_id);

                    artifacts.push(artifact);

                    // Timeline event: file-entry shell items embed a FAT/DOS
                    // last-modified stamp. Emit one only when it is present and
                    // valid; other item classes (GUID folders, volumes, network)
                    // carry no timestamp and are skipped.
                    if let Some(event) = shellbag_timeline_event(
                        self.case_id,
                        self.parent_id,
                        &full_path,
                        shell_item_data,
                    ) {
                        artifacts.push(event);
                    }

                    let children = self.parse_bag_mru_depth(&subkey, &full_path, depth + 1);
                    artifacts.extend(children);
                }
            }
        }

        artifacts
    }

    /// Decide whether the walk may descend to `depth`.
    ///
    /// `None` means carry on. `Some(records)` stops the walk and carries the
    /// records that must reach the case in its place — never an empty vec, which
    /// would erase the untraversed subtree without saying so (B2-167).
    pub(crate) fn depth_guard(&self, parent_path: &str, depth: usize) -> Option<Vec<Artifact>> {
        if depth > MAX_BAGMRU_DEPTH {
            Some(vec![
                self.walk_truncated_artifact(parent_path, MAX_BAGMRU_DEPTH)
            ])
        } else {
            None
        }
    }

    /// The record that stands for the part of the BagMRU tree this walk refused
    /// to descend into.
    ///
    /// Forensic meaning: folders below `parent_path` may have been browsed and
    /// are not listed. Their absence from the bag list is the tool's limit, not
    /// the user's behaviour.
    fn walk_truncated_artifact(&self, parent_path: &str, max_depth: usize) -> Artifact {
        Artifact::new(
            self.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "ShellBagWalkTruncated",
                "record_type": "shellbag_walk_truncated",
                "name": format!("BagMRU walk stopped at {}", parent_path),
                "path": parent_path,
                "max_depth": max_depth,
                "content_incomplete": true,
                "content_incomplete_reason": "bagmru_depth_limit",
                "message": "The BagMRU tree nests deeper than this parser will walk (a corrupt \
                            or hostile hive can loop). Folders below this path are not listed, \
                            and their absence is not evidence that they were never opened",
            }),
        )
        .with_parent(self.parent_id)
    }
}

/// Build a `TimelineEvent` artifact for a shell bag entry that carries a DOS
/// last-modified time. Returns `None` when the shell item has no usable
/// timestamp (e.g. GUID folders, volumes, network locations).
pub(crate) fn shellbag_timeline_event(
    case_id: Uuid,
    parent_id: Uuid,
    full_path: &str,
    data: &[u8],
) -> Option<Artifact> {
    let mtime = shell_item_mtime(data)?;
    Some(
        Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": mtime.to_rfc3339(),
                "timestamp_desc": "ShellBag Modified (FAT)",
                // The embedded DOS/FAT time is host LOCAL wall-clock with no
                // zone; it is rendered here as an RFC3339 string but is NOT UTC.
                // Tag it "local" (like the FAT plugin) so consumers don't shift
                // it by a false zero offset (BUG-107).
                "timezone": "local",
                "source_module": "plugin.windows.shellbags",
                "short_desc": format!("ShellBag: {}", full_path),
                "path": full_path,
            }),
        )
        .with_parent(parent_id),
    )
}

/// The `ShellBagEntry` record for one shell item.
///
/// Lifted out of the walk so it can be tested without building a registry
/// hive: the record used to carry **no time at all** — the modification time
/// reached a timeline event and nothing else, and the creation and access
/// times in the `BEEF0004` block were never read (`ROADMAP` §5.16) — and a
/// field nothing can test is a field nobody can rely on.
pub(crate) fn shellbag_entry_metadata(
    full_path: &str,
    folder_name: &str,
    slot: &str,
    data: &[u8],
) -> serde_json::Value {
    let times = shell_item_times(data);
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("ShellBagEntry"));
    meta.insert("path".into(), json!(full_path));
    meta.insert("folder_name".into(), json!(folder_name));
    meta.insert("slot".into(), json!(slot));
    for (key, value) in [
        ("folder_modified", times.modified),
        ("folder_created", times.created),
        ("folder_accessed", times.accessed),
    ] {
        if let Some(t) = value {
            meta.insert(key.into(), json!(t.to_rfc3339()));
        }
    }
    if times.modified.is_some() || times.created.is_some() || times.accessed.is_some() {
        // FAT date/time pairs: local wall-clock with no recorded zone.
        // Rendered RFC 3339 so every date in a case has one shape, but they
        // are NOT UTC and must not be shifted by a false zero offset
        // (`BUG-107`).
        meta.insert("timezone".into(), json!("local"));
        meta.insert("timestamp_note".into(), json!(FAT_TIME_NOTE));
    }
    serde_json::Value::Object(meta)
}

/// Add the last-write time of the BagMRU key that holds this folder's slot.
///
/// The shell item's own FAT times say when the *folder* was created, modified
/// and accessed on its volume. The key's last-write time says something else:
/// when Windows last wrote this folder's entry in the user's bag list, which is
/// when the user first browsed to it or next re-ordered the list by opening it.
/// That is the "ShellBag timestamp" published answer keys quote (the NIST CFReDS
/// Data Leakage key's questions 25 and 27), and until 2026-09-30 it was on the
/// hive record only, not on the bag: a bag read as a folder listing carried no
/// time the examiner could tie to the user's act (`VALIDATION.md` `LEAK-2`).
///
/// A zero FILETIME is not a time and is left off.
pub(crate) fn with_key_last_written(
    mut meta: serde_json::Value,
    last_written_filetime: u64,
) -> serde_json::Value {
    if let (Some(obj), Some(when)) = (
        meta.as_object_mut(),
        seance_core::time::filetime_to_rfc3339(last_written_filetime),
    ) {
        obj.insert("key_last_written".into(), json!(when));
        obj.insert(
            "key_last_written_basis".into(),
            json!(
                "the last-write time of the BagMRU key that holds this folder's slot, in UTC. \
                 Windows writes it when the folder's entry is created and when the list is \
                 re-ordered by opening the folder again, so it is the latest such act, not \
                 proof of the first. The folder's own FAT times are separate fields and are \
                 local wall-clock"
            ),
        );
    }
    meta
}
