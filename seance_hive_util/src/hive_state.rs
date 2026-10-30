//! Detection of a registry hive whose most recent changes are still only in its
//! transaction logs.
//!
//! A hive copied off a running (or crashed) Windows system is frequently
//! **dirty**: the last writes live in `NTUSER.DAT.LOG1` / `.LOG2` and have not
//! been flushed into the primary file. A parser that reads the primary file
//! alone reports the state as of the last flush, which can be hours or days
//! stale.
//!
//! Forensic meaning: the keys this parser reports are real, but the *absence*
//! of a key is not evidence of absence — the most recent folder access,
//! execution, or install may exist only in the unreplayed log. Reporting a
//! stale hive as if it were the captured state is the failure mode this module
//! exists to prevent. Full replay is implemented in the registry plugin
//! (`seance_plugin_registry::reglog`); the plugins that use this module cannot
//! reach it, so they detect the condition and stamp it on every artifact they
//! emit instead of presenting stale keys as current.
//!
//! Note: this module lives in its own crate precisely so that the hive-reading
//! plugins, which must not depend on the registry plugin, still share one
//! implementation. Keep the stamped key names identical to
//! `seance_plugin_registry::stamp_replay_provenance` — they are an API/frontend
//! contract.

use crate::add_incomplete_reason;
use seance_core::artifact::{Artifact, ArtifactType};
use std::path::PathBuf;

/// Offset of the base-block XOR-32 checksum, and the end of the region it covers.
const CHECKSUM_OFFSET: usize = 0x1FC;
/// Minimum bytes needed to judge the base block.
const BASE_BLOCK_MIN: usize = 0x200;

/// Reason stamped when a dirty hive's logs are present but this parser cannot
/// replay them. Never claim recovery that did not happen.
const REASON_UNSUPPORTED: &str = "replay_not_supported_by_this_parser";

/// Reason stamped when the hive itself was not loaded in full.
const REASON_TRUNCATED: &str = "hive_not_read_in_full";

/// What is known about a hive's recovery state at parse time.
pub struct HiveRecoveryState {
    /// The base block says the hive was not cleanly flushed.
    pub dirty: bool,
    /// Names of the transaction logs found beside the hive.
    pub logs_found: Vec<String>,
    /// Bytes actually loaded for parsing.
    pub bytes_read: u64,
    /// Bytes the source says the hive holds.
    pub declared_bytes: u64,
}

impl HiveRecoveryState {
    /// True when recent evidence is known to be missing from what was parsed:
    /// the hive is dirty *and* the logs holding the pending writes are here.
    pub fn evidence_pending_in_logs(&self) -> bool {
        self.dirty && !self.logs_found.is_empty()
    }

    /// True when only a prefix of the hive was loaded, because the load cap cut
    /// it short or the source stopped returning bytes.
    ///
    /// Forensic meaning: the keys of a hive are spread over the whole file, so a
    /// prefix is not "the first N keys" — it is an arbitrary subset. Anything
    /// this parser reports from a short load is real, but its silence about a
    /// key is meaningless.
    pub fn truncated(&self) -> bool {
        self.bytes_read < self.declared_bytes
    }

    /// True when what was parsed is known not to be the whole hive, for either
    /// reason.
    pub fn incomplete(&self) -> bool {
        self.evidence_pending_in_logs() || self.truncated()
    }

    /// Stable identifier for why the parse is incomplete, or `None` when the
    /// whole hive was loaded and nothing is pending in a log.
    fn incomplete_reason(&self) -> Option<&'static str> {
        if self.truncated() {
            Some(REASON_TRUNCATED)
        } else if self.evidence_pending_in_logs() {
            Some(REASON_UNSUPPORTED)
        } else {
            None
        }
    }
}

/// XOR-32 of the base block header, with the two values Windows never stores.
fn checksum_xor32(buf: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for chunk in buf[..CHECKSUM_OFFSET].as_chunks::<4>().0.iter() {
        sum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    match sum {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        other => other,
    }
}

/// Inspect a hive buffer and its surroundings for pending transaction logs.
///
/// A buffer too short to hold a base block, or one that is not a primary hive,
/// is reported as not dirty: this module must never invent a recovery warning
/// for something that is not a hive.
pub fn inspect(artifact: &Artifact, hive: &[u8]) -> HiveRecoveryState {
    let dirty = hive_is_dirty(hive);
    let bytes_read = hive.len() as u64;
    HiveRecoveryState {
        dirty,
        logs_found: discover_log_names(artifact),
        bytes_read,
        // No data source means the buffer is all there ever was; comparing
        // against zero would invent a truncation.
        declared_bytes: artifact
            .data
            .as_ref()
            .map(|d| d.size())
            .unwrap_or(bytes_read),
    }
}

/// True when the base block reports an interrupted flush: mismatched sequence
/// numbers, or a header checksum that does not verify.
fn hive_is_dirty(hive: &[u8]) -> bool {
    if hive.len() < BASE_BLOCK_MIN || &hive[0..4] != b"regf" {
        return false;
    }
    // file_type: 0 = primary hive. A log fed in directly is not our concern.
    let file_type = u32::from_le_bytes([hive[0x1C], hive[0x1D], hive[0x1E], hive[0x1F]]);
    if file_type != 0 {
        return false;
    }
    let primary_seq = u32::from_le_bytes([hive[4], hive[5], hive[6], hive[7]]);
    let secondary_seq = u32::from_le_bytes([hive[8], hive[9], hive[10], hive[11]]);
    let stored = u32::from_le_bytes([
        hive[CHECKSUM_OFFSET],
        hive[CHECKSUM_OFFSET + 1],
        hive[CHECKSUM_OFFSET + 2],
        hive[CHECKSUM_OFFSET + 3],
    ]);
    primary_seq != secondary_seq || stored != checksum_xor32(hive)
}

/// Names of the `.LOG1`/`.LOG2`/`.LOG` files reachable beside the hive, either
/// on the local filesystem or as siblings inside the evidence container.
fn discover_log_names(artifact: &Artifact) -> Vec<String> {
    let base_path = artifact
        .metadata
        .get("source_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .or_else(|| artifact.data.as_ref().and_then(|d| d.get_underlying_path()));
    let file_name = artifact
        .metadata
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("hive");

    let exists = |suffix: &str| -> bool {
        for s in [suffix.to_string(), suffix.to_ascii_lowercase()] {
            if let Some(base) = base_path.as_ref() {
                let path = PathBuf::from(format!("{}{}", base.to_string_lossy(), s));
                if std::fs::metadata(&path).is_ok() {
                    return true;
                }
            }
            if let Some(ds) = artifact.data.as_ref() {
                if ds.open_sibling(&s).is_some() {
                    return true;
                }
            }
        }
        false
    };

    let mut names = Vec::new();
    for suffix in [".LOG1", ".LOG2"] {
        if exists(suffix) {
            names.push(format!("{}{}", file_name, suffix));
        }
    }
    if names.is_empty() && exists(".LOG") {
        names.push(format!("{}.LOG", file_name));
    }
    names
}

/// Stamp the recovery state onto an artifact's metadata object.
///
/// Always stamped, so "clean hive" and "nobody checked" cannot render
/// identically. `content_incomplete` is set only when writes are known to be
/// pending in a log that was found but not replayed.
pub fn stamp(metadata: &mut serde_json::Value, state: &HiveRecoveryState) {
    let Some(map) = metadata.as_object_mut() else {
        return;
    };
    map.insert("hive_dirty".into(), serde_json::json!(state.dirty));
    map.insert("logs_replayed".into(), serde_json::json!(false));
    map.insert("log_files".into(), serde_json::json!(state.logs_found));
    map.insert(
        "replay_reason".into(),
        serde_json::json!(if state.evidence_pending_in_logs() {
            REASON_UNSUPPORTED
        } else if state.dirty {
            "dirty_but_no_logs_found"
        } else {
            "clean"
        }),
    );
    // Always stated: a hive read in full and a hive cut short by the load cap
    // must not produce the same record.
    map.insert(
        "hive_truncated".into(),
        serde_json::json!(state.truncated()),
    );
    if state.truncated() {
        map.insert(
            "hive_bytes_read".into(),
            serde_json::json!(state.bytes_read),
        );
        map.insert(
            "hive_declared_bytes".into(),
            serde_json::json!(state.declared_bytes),
        );
    }
    if let Some(reason) = state.incomplete_reason() {
        // Merged, never overwritten. A per-record walk can stamp its own reason
        // before or after this runs (`cap_reached` for an entry cap,
        // `unresolved_structure` for a record stream that stopped,
        // `bagmru_depth_limit` for a bag tree that nests too deep); a plain
        // insert here erased it, so a capped walk on a dirty hive reported only
        // "the hive was not read in full" and the examiner lost the fact that
        // the walk itself was truncated.
        add_incomplete_reason(map, reason);
    }
}

/// Build the record that carries a hive's recovery state when the parse itself
/// produced nothing.
///
/// Forensic meaning: with no artifacts to stamp, a dirty or truncated hive
/// returns exactly what a clean, fully-read, genuinely empty hive returns —
/// nothing. That is the one outcome an examiner must never see, because it
/// reads as "this user opened no folders" / "this machine ran no programs".
pub fn status_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    hive_name: &str,
    state: &HiveRecoveryState,
) -> Artifact {
    let mut metadata = serde_json::json!({
        "type": "RegistryHiveParseStatus",
        "record_type": "registry_hive_parse_status",
        "name": format!("{} (no records recovered)", hive_name),
        "hive_name": hive_name,
        "message": "This hive yielded no records, and it was not read in the state it was \
                    captured in: the absence of entries below is not evidence that none exist",
    });
    stamp(&mut metadata, state);
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}

/// Record that a file named as a hive **would not open at all**.
///
/// Separate from [`status_artifact`], which is for a hive that opened and
/// yielded nothing. This one is the answer to "what happened to
/// `UsrClass.dat`" when the file is not a hive, is truncated below the base
/// block, or fails its own checksum — and without it the case shows no records
/// and no reason, which reads as a user who did the thing the parser looks for
/// and left no trace of it.
///
/// `what` names what was being looked for, in the words the parser's own
/// records use — "shellbags", "the AppCompatCache" — because the absence an
/// examiner has to reason about is the absence of those, not of a hive.
pub fn unreadable_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    hive_name: &str,
    what: &str,
    error: &str,
    state: &HiveRecoveryState,
) -> Artifact {
    let mut metadata = serde_json::json!({
        "type": "RegistryHiveParseStatus",
        "record_type": "registry_hive_parse_status",
        "name": format!("{hive_name} (not read)"),
        "hive_name": hive_name,
        "looked_for": what,
        "failure_detail": error,
        "message": format!(
            concat!(
                "This file is named as a registry hive but could not be opened, so ",
                "{} were never looked for in it. The absence of them in this case is ",
                "NOT evidence that there were none: nothing here read the file. ",
                "Reason: {}"
            ),
            what,
            error
        ),
    });
    stamp(&mut metadata, state);
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file named as a hive that will not open must leave a record saying
    /// so. Silence is indistinguishable from a hive that held nothing.
    #[test]
    fn a_hive_that_will_not_open_leaves_a_record_naming_what_was_not_looked_for() {
        let state = HiveRecoveryState {
            dirty: false,
            logs_found: Vec::new(),
            bytes_read: 64,
            declared_bytes: 64,
        };
        let a = unreadable_artifact(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "UsrClass.dat",
            "shellbags",
            "not a registry hive: no regf signature",
            &state,
        );
        assert_eq!(a.metadata["type"], "RegistryHiveParseStatus");
        assert_eq!(a.metadata["looked_for"], "shellbags");
        let message = a.metadata["message"].as_str().expect("a message");
        assert!(
            message.contains("shellbags were never looked for"),
            "{message}"
        );
        assert!(
            message.contains("NOT evidence that there were none"),
            "{message}"
        );
        assert!(message.contains("no regf signature"), "{message}");
    }

    /// Build a base block: `regf`, the two sequence numbers, a primary
    /// file type, and a checksum that matches unless asked to corrupt it.
    fn base_block(primary_seq: u32, secondary_seq: u32, good_checksum: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[0..4].copy_from_slice(b"regf");
        buf[4..8].copy_from_slice(&primary_seq.to_le_bytes());
        buf[8..12].copy_from_slice(&secondary_seq.to_le_bytes());
        buf[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes()); // primary hive
        let sum = checksum_xor32(&buf);
        let stored = if good_checksum { sum } else { sum ^ 0xDEAD };
        buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&stored.to_le_bytes());
        buf
    }

    #[test]
    fn a_hive_flushed_cleanly_is_not_reported_as_dirty() {
        assert!(!hive_is_dirty(&base_block(7, 7, true)));
    }

    #[test]
    fn mismatched_sequence_numbers_mean_the_last_writes_are_still_in_the_log() {
        assert!(hive_is_dirty(&base_block(8, 7, true)));
    }

    #[test]
    fn a_base_block_whose_checksum_does_not_verify_is_treated_as_dirty() {
        assert!(hive_is_dirty(&base_block(7, 7, false)));
    }

    #[test]
    fn a_non_hive_or_truncated_buffer_never_fabricates_a_recovery_warning() {
        assert!(!hive_is_dirty(&[]));
        assert!(!hive_is_dirty(&[0u8; 16]));
        let mut not_a_hive = base_block(8, 7, true);
        not_a_hive[0..4].copy_from_slice(b"nope");
        assert!(!hive_is_dirty(&not_a_hive));
        // A transaction log fed in directly is not a primary hive.
        let mut log = base_block(8, 7, true);
        log[0x1C..0x20].copy_from_slice(&6u32.to_le_bytes());
        assert!(!hive_is_dirty(&log));
    }

    /// A state describing a hive that was read in full, with the given dirty
    /// flag and log names.
    fn state_read_in_full(dirty: bool, logs_found: Vec<String>) -> HiveRecoveryState {
        HiveRecoveryState {
            dirty,
            logs_found,
            bytes_read: 4096,
            declared_bytes: 4096,
        }
    }

    #[test]
    fn a_clean_hive_is_stamped_as_clean_rather_than_left_unmarked() {
        let state = state_read_in_full(false, Vec::new());
        let mut md = serde_json::json!({});
        stamp(&mut md, &state);
        assert_eq!(md["hive_dirty"], false);
        assert_eq!(md["logs_replayed"], false);
        assert_eq!(md["replay_reason"], "clean");
        assert_eq!(md["hive_truncated"], false);
        assert!(
            md.get("content_incomplete").is_none(),
            "a clean hive is complete; do not warn about it"
        );
    }

    #[test]
    fn a_dirty_hive_with_logs_beside_it_is_marked_incomplete_and_names_the_logs() {
        let state = state_read_in_full(true, vec!["NTUSER.DAT.LOG1".to_string()]);
        assert!(state.evidence_pending_in_logs());
        let mut md = serde_json::json!({});
        stamp(&mut md, &state);
        assert_eq!(md["hive_dirty"], true);
        assert_eq!(md["logs_replayed"], false);
        assert_eq!(md["replay_reason"], REASON_UNSUPPORTED);
        assert_eq!(md["log_files"][0], "NTUSER.DAT.LOG1");
        assert_eq!(md["content_incomplete"], true);
        assert_eq!(md["content_incomplete_reason"], REASON_UNSUPPORTED);
    }

    #[test]
    fn a_dirty_hive_with_no_logs_says_so_instead_of_claiming_pending_evidence() {
        let state = state_read_in_full(true, Vec::new());
        assert!(!state.evidence_pending_in_logs());
        let mut md = serde_json::json!({});
        stamp(&mut md, &state);
        assert_eq!(md["replay_reason"], "dirty_but_no_logs_found");
        assert!(md.get("content_incomplete").is_none());
    }

    #[test]
    fn a_hive_the_load_cap_cut_short_is_reported_as_a_partial_hive() {
        // The load stopped at 512 MiB of a 900 MiB file. Every key past that
        // point is missing, and nothing in the emitted records would otherwise
        // show it.
        let state = HiveRecoveryState {
            dirty: false,
            logs_found: Vec::new(),
            bytes_read: 512 * 1024 * 1024,
            declared_bytes: 900 * 1024 * 1024,
        };
        assert!(state.truncated());
        assert!(state.incomplete());

        let mut md = serde_json::json!({});
        stamp(&mut md, &state);
        assert_eq!(md["hive_truncated"], true);
        assert_eq!(md["content_incomplete"], true);
        assert_eq!(md["content_incomplete_reason"], REASON_TRUNCATED);
        assert_eq!(md["hive_bytes_read"], 512u64 * 1024 * 1024);
        assert_eq!(md["hive_declared_bytes"], 900u64 * 1024 * 1024);
        // A clean base block must not turn a short load into a replay claim.
        assert_eq!(md["replay_reason"], "clean");
    }

    /// A per-record walk stamps its own reason before this module runs
    /// (shimcache's AppCompatCache walk, shellbags' BagMRU depth limit).
    /// Overwriting it lost the fact that the walk itself was capped or
    /// truncated, leaving only "the hive was not read in full" — a different
    /// follow-up, and the wrong one.
    #[test]
    fn a_reason_already_stamped_by_the_cache_walk_survives_the_hive_stamp() {
        let state = HiveRecoveryState {
            dirty: false,
            logs_found: Vec::new(),
            bytes_read: 1024,
            declared_bytes: 4096,
        };
        let mut md = serde_json::json!({
            "content_incomplete": true,
            "content_incomplete_reason": "cap_reached",
        });
        stamp(&mut md, &state);
        // Owned, because the second `stamp` below needs `md` mutably and a
        // borrowed `&str` into it would still be live.
        let reason = md["content_incomplete_reason"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            reason.split('+').any(|r| r == "cap_reached"),
            "the cache walk's reason must not be erased: {reason}"
        );
        assert!(
            reason.split('+').any(|r| r == REASON_TRUNCATED),
            "the hive's own reason must still be present: {reason}"
        );

        // Stamping twice must not duplicate a reason.
        stamp(&mut md, &state);
        assert_eq!(md["content_incomplete_reason"].as_str().unwrap(), reason);
    }

    /// The other stamp order. Amcache stamps the hive state first and its walk
    /// tally second; shellbags' depth-limit record carries its reason before the
    /// hive stamp runs. Both orders must end with both reasons on the record.
    #[test]
    fn a_reason_added_after_the_hive_stamp_does_not_erase_the_hives_own() {
        let state = HiveRecoveryState {
            dirty: true,
            logs_found: vec!["Amcache.hve.LOG1".to_string()],
            bytes_read: 4096,
            declared_bytes: 4096,
        };
        let mut md = serde_json::json!({});
        stamp(&mut md, &state);
        assert_eq!(md["content_incomplete_reason"], REASON_UNSUPPORTED);

        add_incomplete_reason(md.as_object_mut().unwrap(), "cap_reached");
        let reason = md["content_incomplete_reason"].as_str().unwrap();
        assert!(
            reason.split('+').any(|r| r == REASON_UNSUPPORTED),
            "the hive's reason must survive a later stage: {reason}"
        );
        assert!(
            reason.split('+').any(|r| r == "cap_reached"),
            "the later stage's reason must be recorded too: {reason}"
        );
    }

    #[test]
    fn a_hive_read_in_full_is_never_reported_as_truncated() {
        let state = state_read_in_full(false, Vec::new());
        assert!(!state.truncated());
        assert!(!state.incomplete());
        assert_eq!(state.incomplete_reason(), None);
    }

    #[test]
    fn a_hive_that_produced_no_records_still_emits_a_status_an_examiner_can_see() {
        // Nothing parsed out of a dirty hive: without this record the case shows
        // exactly what a clean, empty hive shows.
        let state = state_read_in_full(true, vec!["SYSTEM.LOG1".to_string()]);
        let case_id = uuid::Uuid::new_v4();
        let parent_id = uuid::Uuid::new_v4();
        let status = status_artifact(case_id, parent_id, "SYSTEM", &state);

        assert_eq!(status.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(status.parent_id, Some(parent_id));
        assert_eq!(status.metadata["type"], "RegistryHiveParseStatus");
        assert_eq!(status.metadata["hive_name"], "SYSTEM");
        assert_eq!(status.metadata["content_incomplete"], true);
        assert_eq!(status.metadata["hive_dirty"], true);
        assert_eq!(status.metadata["log_files"][0], "SYSTEM.LOG1");
    }

    #[test]
    fn transaction_logs_lying_beside_the_hive_on_disk_are_discovered_by_name() {
        let dir = std::env::temp_dir().join(format!("seance_hive_state_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let hive_path = dir.join("NTUSER.DAT");
        std::fs::write(&hive_path, b"regf").unwrap();
        std::fs::write(dir.join("NTUSER.DAT.LOG1"), b"regf").unwrap();

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            serde_json::json!({
                "name": "NTUSER.DAT",
                "source_path": hive_path.to_string_lossy(),
            }),
        );
        let found = discover_log_names(&artifact);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(found, vec!["NTUSER.DAT.LOG1".to_string()]);
    }

    #[test]
    fn a_hive_with_no_logs_beside_it_reports_none_found() {
        let dir = std::env::temp_dir().join(format!("seance_hive_state_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let hive_path = dir.join("NTUSER.DAT");
        std::fs::write(&hive_path, b"regf").unwrap();

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            serde_json::json!({
                "name": "NTUSER.DAT",
                "source_path": hive_path.to_string_lossy(),
            }),
        );
        let found = discover_log_names(&artifact);
        std::fs::remove_dir_all(&dir).ok();
        assert!(found.is_empty());
    }
}
