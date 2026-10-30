//! Public transaction-log (`.LOG1` / `.LOG2`) API for Windows registry hives.
//!
//! This is the crate's **exported** surface for registry transaction-log replay:
//! the crate-internal `reglog` engine parses and applies the logs, and this
//! module supplies everything a *plugin* needs around it — finding the logs
//! beside a hive artifact, running the replay, and stamping the outcome onto the
//! records it emits.
//!
//! # Why a plugin should use this
//!
//! A hive copied off a running (or crashed) Windows system is frequently
//! **dirty**: its most recent writes live only in `<hive>.LOG1` / `.LOG2` and
//! have not been flushed into the primary file. A parser that reads the primary
//! file alone reports the registry as it stood at the last flush. What an
//! examiner then sees is real but incomplete, and the failure is silent: the
//! newest Run key, the last USB device, the most recent folder opened, the
//! program installed minutes before acquisition can all be missing, and nothing
//! in the output says so.
//!
//! Any plugin that reads a hive — ShellBags (`UsrClass.dat`), Amcache
//! (`Amcache.hve`), Shimcache (`SYSTEM`), user-assist, and so on — should route
//! its buffer through [`recover_artifact_hive`] before parsing, then call
//! [`HiveRecovery::stamp`] on every record it emits:
//!
//! ```ignore
//! use seance_plugin_registry::txlog;
//!
//! // A transaction log shares the `regf` magic with a hive; never parse one
//! // as if it were the hive itself.
//! if txlog::is_transaction_log(&buffer) {
//!     return Ok(Vec::new());
//! }
//!
//! let recovery = txlog::recover_artifact_hive(artifact, &buffer);
//! let hive = recovery.hive(); // replayed bytes, or the original if nothing applied
//! // ... parse `hive` ...
//! recovery.stamp(&mut record_metadata);           // full provenance on the hive record
//! child.metadata["replay"] = recovery.child_stamp(); // compact flag on each child
//! ```
//!
//! # What a wrong answer looks like
//!
//! - A record stamped `logs_replayed: true` whose values came from the on-disk
//!   hive would tell an examiner the state is current when it is stale — the
//!   worst outcome, and the reason every failure path here refuses to claim
//!   recovery.
//! - A record with **no** stamp at all is equally wrong in the other direction:
//!   "clean hive" and "nobody checked" must never render the same, so
//!   [`HiveRecovery::stamp`] writes its keys unconditionally.

use seance_core::artifact::Artifact;
use seance_core::data_source::DataSource;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use crate::reglog::{
    hive_file_type, is_log_file_type, parse_base_block, recover_hive, BaseBlock, ReplayProvenance,
};

/// Cap on how much of one transaction log is loaded.
///
/// Logs are normally KB–MB. The cap exists so a corrupt or hostile size cannot
/// pull an unbounded allocation into the worker; it mirrors the SQLite parser's
/// sidecar cap. A log cut short by this cap is recorded in
/// [`HiveRecovery::logs_truncated`] and stamped — a capped read must never be
/// mistaken for a short log.
pub const MAX_LOG_BYTES: u64 = 512 * 1024 * 1024;

/// The dual-log suffixes Windows 8.1+ alternates between, in the order tried.
const LOG_SUFFIXES: [&str; 2] = [".LOG1", ".LOG2"];

/// The single-log suffix used on pre-Win8.1 hives (and left behind as an
/// install-image dummy on newer ones), consulted only when neither numbered log
/// is reachable.
const LEGACY_LOG_SUFFIX: &str = ".LOG";

/// Metadata reason recorded when a log was cut short by [`MAX_LOG_BYTES`] or by
/// a short read from its source.
const REASON_LOG_CAPPED: &str = "transaction_log_read_capped";

/// Metadata reason recorded when the hive was dirty and no log entry could be
/// applied: what was parsed predates the last writes.
const REASON_DIRTY_UNRECOVERED: &str = "dirty_hive_not_recovered";

/// Metadata reason recorded when replay applied some entries but stopped early
/// (gap, bad hash, out-of-range page): the hive is newer than it was on disk,
/// but still not the state at acquisition.
const REASON_PARTIAL_REPLAY: &str = "partial_log_replay";

/// One transaction log as loaded, with whether the load was complete.
struct LoadedLog {
    bytes: Vec<u8>,
    /// The source declared more bytes than were read (cap or short read).
    truncated: bool,
}

/// The transaction logs found beside a hive artifact.
///
/// `names` are the on-disk file names (for provenance), `truncated` names the
/// subset whose load was cut short. An empty `names` means the logs were not
/// reachable — which is a different statement from "the hive was clean", and the
/// two are kept distinct all the way to the artifact.
#[derive(Debug, Default)]
pub struct DiscoveredLogs {
    /// Bytes of `<hive>.LOG1`, or of the legacy `<hive>.LOG` when neither
    /// numbered log exists.
    pub log1: Option<Vec<u8>>,
    /// Bytes of `<hive>.LOG2`.
    pub log2: Option<Vec<u8>>,
    /// On-disk names of the logs that were loaded, e.g. `["SYSTEM.LOG1"]`.
    pub names: Vec<String>,
    /// Names of the logs whose load was cut short by the cap or a short read.
    pub truncated: Vec<String>,
}

/// The result of recovering a hive: the bytes to parse, why they are what they
/// are, and what was incomplete about getting there.
///
/// `bytes` borrows the caller's buffer when nothing was applied (the clean-hive
/// path costs no copy) and owns a patched buffer when entries were replayed.
pub struct HiveRecovery<'a> {
    /// The hive to parse: replayed where replay succeeded, the original bytes
    /// otherwise. Never a partially-applied *entry* — the engine validates a
    /// whole log entry before it writes any of its pages.
    pub bytes: Cow<'a, [u8]>,
    /// Full provenance of the replay attempt.
    pub provenance: ReplayProvenance,
    /// Logs whose load was cut short; empty when every discovered log was read
    /// in full.
    pub logs_truncated: Vec<String>,
}

impl HiveRecovery<'_> {
    /// The bytes to parse.
    pub fn hive(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// True when what will be parsed is known not to be the hive's state at
    /// acquisition: a dirty hive that was not (or only partly) recovered, or a
    /// log that was not read in full.
    ///
    /// Forensic meaning: when this is true, the *absence* of a key in the output
    /// is not evidence that the key did not exist on the live system.
    pub fn incomplete(&self) -> bool {
        self.incomplete_reason().is_some()
    }

    /// Stable identifier for why the parsed state is not the acquisition state,
    /// or `None` when the hive was clean or fully recovered from logs read in
    /// full.
    pub fn incomplete_reason(&self) -> Option<&'static str> {
        if !self.logs_truncated.is_empty() {
            Some(REASON_LOG_CAPPED)
        } else if self.provenance.dirty && !self.provenance.replayed {
            Some(REASON_DIRTY_UNRECOVERED)
        } else if self.provenance.replayed && self.provenance.reason != "recovered" {
            Some(REASON_PARTIAL_REPLAY)
        } else {
            None
        }
    }

    /// Write the full replay provenance onto a record's metadata object.
    ///
    /// Always writes, including for a clean hive, so that "clean" and "never
    /// checked" cannot produce the same record. Adds the incompleteness flags
    /// when the parsed state is known to trail the evidence.
    pub fn stamp(&self, metadata: &mut Value) {
        stamp_replay_provenance(metadata, &self.provenance);
        let Some(map) = metadata.as_object_mut() else {
            return;
        };
        map.insert(
            "replay_log_read_truncated".into(),
            json!(!self.logs_truncated.is_empty()),
        );
        if !self.logs_truncated.is_empty() {
            map.insert("replay_truncated_logs".into(), json!(self.logs_truncated));
        }
        if let Some(reason) = self.incomplete_reason() {
            map.insert("content_incomplete".into(), json!(true));
            map.insert("content_incomplete_reason".into(), json!(reason));
        }
    }

    /// A compact provenance object for records *derived* from the hive (a USB
    /// device, a typed URL, a shellbag), stamped under a `"replay"` key.
    ///
    /// Those records outlive their hive record in lists, exports and reports, so
    /// each carries enough to answer "was this read from the recovered hive?"
    /// without a lookup.
    pub fn child_stamp(&self) -> Value {
        json!({
            "recovered": self.provenance.replayed,
            "hive_dirty": self.provenance.dirty,
            "reason": self.provenance.reason,
            "incomplete_reason": self.incomplete_reason(),
        })
    }
}

/// True when this buffer is a transaction log rather than a primary hive.
///
/// `.LOG1` / `.LOG2` begin with the same `regf` base block as a hive, so
/// content-based file detection classifies them as hives. A plugin that parses
/// one as a hive emits a junk or empty record for a file that is really the
/// *pending changes* of another file — a record an examiner would read as "this
/// hive is empty". Gate on this before parsing.
pub fn is_transaction_log(buf: &[u8]) -> bool {
    hive_file_type(buf).is_some_and(is_log_file_type)
}

/// Load one log by suffix from the local filesystem beside `base`.
///
/// Tries the canonical spelling and its lower-case form, because both `.LOG1`
/// and `.log1` occur on real evidence and case-sensitive filesystems preserve
/// whichever was written.
fn read_fs(base: &Path, suffix: &str) -> Option<LoadedLog> {
    use std::io::Read;
    for s in [suffix.to_string(), suffix.to_ascii_lowercase()] {
        let path = PathBuf::from(format!("{}{}", base.to_string_lossy(), s));
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file.take(MAX_LOG_BYTES).read_to_end(&mut bytes).is_err() || bytes.is_empty() {
            continue;
        }
        let truncated = (bytes.len() as u64) < meta.len();
        return Some(LoadedLog { bytes, truncated });
    }
    None
}

/// Load one log by suffix through the data source's sibling contract.
///
/// This is the route that reaches a log inside a container (ZIP, backup) or, on
/// a disk image, one attached by the filesystem parser via
/// `seance_core::data_source::SiblingBundleSource`.
fn read_sibling(ds: &Arc<dyn DataSource>, suffix: &str) -> Option<LoadedLog> {
    for s in [suffix.to_string(), suffix.to_ascii_lowercase()] {
        let Some(sib) = ds.open_sibling(&s) else {
            continue;
        };
        let declared = sib.size();
        let bytes = seance_core::io::read_capped(sib.as_ref(), MAX_LOG_BYTES);
        if bytes.is_empty() {
            continue;
        }
        let truncated = (bytes.len() as u64) < declared;
        return Some(LoadedLog { bytes, truncated });
    }
    None
}

/// Locate and load the `.LOG1` / `.LOG2` (or legacy `.LOG`) transaction logs
/// beside a hive artifact.
///
/// Two routes, mirroring the SQLite parser's `discover_sidecars`:
///
/// 1. **Local filesystem** — `<hive>.LOG1` next to the hive, reached through the
///    artifact's `source_path` metadata or its data source's underlying path.
/// 2. **Sibling through the data source** — `open_sibling(".LOG1")`, which
///    reaches logs inside a container or attached to a disk-image file entry.
///
/// Discovery is by name because that is how Windows itself pairs a hive with its
/// logs, but nothing found here is *trusted*: the replay engine validates every
/// base block, sequence number and hash before a byte is applied.
pub fn discover_logs(artifact: &Artifact) -> DiscoveredLogs {
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
        .unwrap_or("hive")
        .to_string();

    let load = |suffix: &str| -> Option<LoadedLog> {
        base_path
            .as_ref()
            .and_then(|b| read_fs(b, suffix))
            .or_else(|| {
                artifact
                    .data
                    .as_ref()
                    .and_then(|ds| read_sibling(ds, suffix))
            })
    };

    let mut out = DiscoveredLogs::default();
    let record = |out: &mut DiscoveredLogs, suffix: &str, log: &LoadedLog| {
        let name = format!("{}{}", file_name, suffix);
        if log.truncated {
            out.truncated.push(name.clone());
        }
        out.names.push(name);
    };

    if let Some(l) = load(LOG_SUFFIXES[0]) {
        record(&mut out, LOG_SUFFIXES[0], &l);
        out.log1 = Some(l.bytes);
    }
    if let Some(l) = load(LOG_SUFFIXES[1]) {
        record(&mut out, LOG_SUFFIXES[1], &l);
        out.log2 = Some(l.bytes);
    }

    // The bare `.LOG` is a pre-Win8.1 arrangement (and, on newer systems, an
    // install-image leftover). Consult it only when neither numbered log is
    // reachable, so a stale dummy never competes with a live log.
    if out.log1.is_none() && out.log2.is_none() {
        if let Some(l) = load(LEGACY_LOG_SUFFIX) {
            record(&mut out, LEGACY_LOG_SUFFIX, &l);
            out.log1 = Some(l.bytes);
        }
    }

    out
}

/// Discover a hive artifact's transaction logs and replay them into `hive`.
///
/// This is the one call a hive-reading plugin needs. `hive` is the primary
/// file's bytes as already loaded by the caller; the returned
/// [`HiveRecovery::bytes`] is what should be parsed.
///
/// Fail closed: an unreachable, unparseable or unverifiable log leaves the
/// original bytes untouched and records why. Recovery is never claimed for
/// bytes that were not actually applied.
pub fn recover_artifact_hive<'a>(artifact: &Artifact, hive: &'a [u8]) -> HiveRecovery<'a> {
    let logs = discover_logs(artifact);
    let (bytes, mut provenance) = recover_hive(hive, logs.log1.as_deref(), logs.log2.as_deref());
    // The byte-only engine cannot know the on-disk names; discovery can.
    provenance.log_files = logs.names;
    HiveRecovery {
        bytes,
        provenance,
        logs_truncated: logs.truncated,
    }
}

/// Insert the replay-provenance keys onto a record's metadata object.
///
/// The key names are the API and frontend contract (the registry-explorer
/// response and the artifact badges read exactly these) and must stay stable.
/// Prefer [`HiveRecovery::stamp`], which also records what was incomplete; use
/// this directly only when calling [`recover_hive`] on raw buffers.
pub fn stamp_replay_provenance(metadata: &mut Value, prov: &ReplayProvenance) {
    let Some(map) = metadata.as_object_mut() else {
        return;
    };
    map.insert("logs_replayed".into(), json!(prov.replayed));
    map.insert("replay_reason".into(), json!(prov.reason));
    map.insert("hive_dirty".into(), json!(prov.dirty));
    map.insert("log_format".into(), json!(prov.log_format));
    map.insert("log_files".into(), json!(prov.log_files));
    map.insert("primary_sequence".into(), json!(prov.primary_seq));
    map.insert("secondary_sequence".into(), json!(prov.secondary_seq));
    map.insert(
        "replay_sequence_start".into(),
        json!(prov.applied_start_seq),
    );
    map.insert("replay_sequence_end".into(), json!(prov.applied_end_seq));
    map.insert("log_entries_applied".into(), json!(prov.entries_applied));
    map.insert("dirty_pages_applied".into(), json!(prov.pages_applied));
    map.insert("replay_bytes_applied".into(), json!(prov.bytes_applied));
    map.insert(
        "hive_last_written_before".into(),
        json!(prov.last_written_before),
    );
    map.insert(
        "hive_last_written_after".into(),
        json!(prov.last_written_after),
    );
    // The changed-key diff is a separate analysis that the engine does not run
    // today. An empty list would read as "the replay altered no keys", which is
    // a claim; the absence of the list plus an explicit flag reads as "nobody
    // worked out what changed", which is the truth.
    let computed = !prov.changed_key_paths.is_empty();
    map.insert("replay_changed_keys_computed".into(), json!(computed));
    if computed {
        map.insert("replay_changed_keys".into(), json!(prov.changed_key_paths));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::artifact::ArtifactType;
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::test_support::TruncatedSource;
    use std::collections::HashMap;
    use uuid::Uuid;

    /// A base block for a primary hive with the given sequence numbers and a
    /// checksum that verifies.
    fn primary_hive(primary_seq: u32, secondary_seq: u32) -> Vec<u8> {
        base_block(primary_seq, secondary_seq, 0)
    }

    /// A `regf` base block padded to 4096 bytes, with a correct XOR-32 checksum.
    fn base_block(primary_seq: u32, secondary_seq: u32, file_type: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x1000];
        buf[0..4].copy_from_slice(b"regf");
        buf[4..8].copy_from_slice(&primary_seq.to_le_bytes());
        buf[8..12].copy_from_slice(&secondary_seq.to_le_bytes());
        buf[0x1C..0x20].copy_from_slice(&file_type.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&0x1000u32.to_le_bytes()); // hive bins data size
        let mut sum: u32 = 0;
        for chunk in buf[..0x1FC].as_chunks::<4>().0.iter() {
            sum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let sum = match sum {
            0 => 1,
            0xFFFF_FFFF => 0xFFFF_FFFE,
            other => other,
        };
        buf[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
        buf.resize(0x2000, 0);
        buf
    }

    /// A hive that can hand out named siblings (`.LOG1`, `.LOG2`), standing in
    /// for a container entry or a `SiblingBundleSource` on a disk image.
    ///
    /// Only the sibling routing is local: every read is answered by a shared
    /// `seance_core` double — `ByteSliceDataSource` when the bytes are whole,
    /// `TruncatedSource` when `declared_extra` makes the source (and its
    /// siblings) claim more than it can serve.
    #[derive(Debug)]
    struct HiveWithLogs {
        bytes: Vec<u8>,
        siblings: HashMap<String, Vec<u8>>,
        /// Report a larger size than can be read, reproducing a short read.
        declared_extra: u64,
    }

    impl HiveWithLogs {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                siblings: HashMap::new(),
                declared_extra: 0,
            }
        }
        fn with_sibling(mut self, suffix: &str, bytes: Vec<u8>) -> Self {
            self.siblings.insert(suffix.to_string(), bytes);
            self
        }
        fn reader(bytes: &[u8], declared_extra: u64) -> Arc<dyn DataSource> {
            if declared_extra == 0 {
                Arc::new(ByteSliceDataSource::new(bytes.to_vec()))
            } else {
                Arc::new(TruncatedSource::new(
                    bytes.to_vec(),
                    bytes.len() as u64 + declared_extra,
                ))
            }
        }
    }

    impl DataSource for HiveWithLogs {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            Self::reader(&self.bytes, self.declared_extra).read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.bytes.len() as u64 + self.declared_extra
        }
        fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
            // A sibling of a short source is short by the same amount, which
            // exercises the short-read path on the log as well as the hive.
            self.siblings
                .get(suffix)
                .map(|b| Self::reader(b, self.declared_extra))
        }
    }

    fn artifact_with(name: &str, source: Option<HiveWithLogs>) -> Artifact {
        let data = source.map(|s| Arc::new(s) as Arc<dyn DataSource>);
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            data,
            json!({ "name": name }),
        )
    }

    #[test]
    fn a_transaction_log_is_recognised_so_it_is_never_parsed_as_a_hive() {
        assert!(
            is_transaction_log(&base_block(3, 3, 6)),
            "new-format HvLE log"
        );
        assert!(is_transaction_log(&base_block(3, 3, 1)), "legacy DIRT log");
        assert!(!is_transaction_log(&primary_hive(3, 3)), "primary hive");
        assert!(!is_transaction_log(b"not a hive at all"));
        assert!(!is_transaction_log(&[]));
    }

    #[test]
    fn a_hive_with_no_logs_beside_it_reports_none_found_rather_than_claiming_recovery() {
        let art = artifact_with("SYSTEM", Some(HiveWithLogs::new(primary_hive(9, 8))));
        let hive = primary_hive(9, 8);
        let rec = recover_artifact_hive(&art, &hive);

        assert!(rec.provenance.dirty, "9/8 is an interrupted flush");
        assert!(!rec.provenance.replayed);
        assert_eq!(rec.provenance.reason, "no_logs_found");
        assert!(rec.provenance.log_files.is_empty());
        assert_eq!(rec.hive(), &hive[..], "no logs means no byte is altered");
    }

    #[test]
    fn a_clean_hive_is_returned_unaltered_and_without_a_copy() {
        let art = artifact_with("SOFTWARE", Some(HiveWithLogs::new(primary_hive(4, 4))));
        let hive = primary_hive(4, 4);
        let rec = recover_artifact_hive(&art, &hive);

        assert!(!rec.provenance.dirty);
        assert!(!rec.provenance.replayed);
        assert_eq!(rec.provenance.reason, "clean");
        assert!(
            matches!(&rec.bytes, Cow::Borrowed(_)),
            "a clean hive must not be copied"
        );
        assert!(!rec.incomplete());
    }

    #[test]
    fn logs_are_discovered_through_the_data_sources_sibling_contract() {
        // The disk-image / container route: no path on disk, siblings attached
        // to the source.
        let src = HiveWithLogs::new(primary_hive(5, 4))
            .with_sibling(".LOG1", base_block(5, 4, 6))
            .with_sibling(".LOG2", base_block(5, 4, 6));
        let art = artifact_with("NTUSER.DAT", Some(src));

        let logs = discover_logs(&art);
        assert!(logs.log1.is_some());
        assert!(logs.log2.is_some());
        assert_eq!(
            logs.names,
            vec!["NTUSER.DAT.LOG1".to_string(), "NTUSER.DAT.LOG2".to_string()]
        );
        assert!(logs.truncated.is_empty());
    }

    #[test]
    fn a_lower_case_log_suffix_is_found_too() {
        let src = HiveWithLogs::new(primary_hive(5, 4)).with_sibling(".log1", base_block(5, 4, 6));
        let art = artifact_with("SYSTEM", Some(src));

        let logs = discover_logs(&art);
        assert!(
            logs.log1.is_some(),
            "case-sensitive evidence still pairs up"
        );
        assert_eq!(logs.names, vec!["SYSTEM.LOG1".to_string()]);
    }

    #[test]
    fn the_legacy_single_log_is_consulted_only_when_no_numbered_log_exists() {
        let with_legacy_only =
            HiveWithLogs::new(primary_hive(5, 4)).with_sibling(".LOG", base_block(5, 4, 1));
        let logs = discover_logs(&artifact_with("SYSTEM", Some(with_legacy_only)));
        assert!(logs.log1.is_some(), "the bare .LOG is the only candidate");
        assert_eq!(logs.names, vec!["SYSTEM.LOG".to_string()]);

        let with_both = HiveWithLogs::new(primary_hive(5, 4))
            .with_sibling(".LOG1", base_block(5, 4, 6))
            .with_sibling(".LOG", base_block(5, 4, 1));
        let logs = discover_logs(&artifact_with("SYSTEM", Some(with_both)));
        assert_eq!(
            logs.names,
            vec!["SYSTEM.LOG1".to_string()],
            "a numbered log wins; the bare .LOG may be an install-image dummy"
        );
    }

    #[test]
    fn logs_beside_the_hive_on_the_local_filesystem_are_found_by_path() {
        let dir = std::env::temp_dir().join(format!("seance_txlog_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let hive_path = dir.join("SYSTEM");
        std::fs::write(&hive_path, primary_hive(5, 4)).unwrap();
        std::fs::write(dir.join("SYSTEM.LOG1"), base_block(5, 4, 6)).unwrap();

        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "SYSTEM", "source_path": hive_path.to_string_lossy() }),
        );
        let logs = discover_logs(&art);
        std::fs::remove_dir_all(&dir).ok();

        assert!(logs.log1.is_some());
        assert!(logs.log2.is_none());
        assert_eq!(logs.names, vec!["SYSTEM.LOG1".to_string()]);
        assert!(logs.truncated.is_empty());
    }

    #[test]
    fn an_empty_log_file_is_not_reported_as_a_discovered_log() {
        let src = HiveWithLogs::new(primary_hive(5, 4)).with_sibling(".LOG1", Vec::new());
        let logs = discover_logs(&artifact_with("SYSTEM", Some(src)));
        assert!(logs.log1.is_none());
        assert!(
            logs.names.is_empty(),
            "naming a log we could not read would overstate what was examined"
        );
    }

    #[test]
    fn a_log_that_could_not_be_read_in_full_is_named_as_truncated() {
        // The source declares more bytes than it serves: the load is short, so
        // entries at the end of the log are missing.
        let mut src =
            HiveWithLogs::new(primary_hive(5, 4)).with_sibling(".LOG1", base_block(5, 4, 6));
        src.declared_extra = 4096;
        let art = artifact_with("SYSTEM", Some(src));

        let logs = discover_logs(&art);
        assert_eq!(logs.truncated, vec!["SYSTEM.LOG1".to_string()]);

        let hive = primary_hive(5, 4);
        let rec = recover_artifact_hive(&art, &hive);
        assert_eq!(rec.logs_truncated, vec!["SYSTEM.LOG1".to_string()]);
        assert!(rec.incomplete());
        assert_eq!(rec.incomplete_reason(), Some(REASON_LOG_CAPPED));

        let mut md = json!({});
        rec.stamp(&mut md);
        assert_eq!(md["replay_log_read_truncated"], true);
        assert_eq!(md["replay_truncated_logs"][0], "SYSTEM.LOG1");
        assert_eq!(md["content_incomplete"], true);
        assert_eq!(md["content_incomplete_reason"], REASON_LOG_CAPPED);
    }

    #[test]
    fn a_clean_hive_is_stamped_as_clean_rather_than_left_unmarked() {
        let art = artifact_with("SOFTWARE", Some(HiveWithLogs::new(primary_hive(4, 4))));
        let hive = primary_hive(4, 4);
        let rec = recover_artifact_hive(&art, &hive);

        let mut md = json!({ "type": "RegistryHive" });
        rec.stamp(&mut md);
        assert_eq!(md["logs_replayed"], false);
        assert_eq!(md["hive_dirty"], false);
        assert_eq!(md["replay_reason"], "clean");
        assert_eq!(md["log_format"], "none");
        assert_eq!(md["primary_sequence"], 4);
        assert_eq!(md["secondary_sequence"], 4);
        assert_eq!(md["replay_log_read_truncated"], false);
        assert!(
            md.get("content_incomplete").is_none(),
            "a clean hive is complete; warning about it would cry wolf"
        );
    }

    #[test]
    fn a_dirty_hive_that_could_not_be_recovered_is_marked_incomplete() {
        let art = artifact_with("SYSTEM", Some(HiveWithLogs::new(primary_hive(9, 8))));
        let hive = primary_hive(9, 8);
        let rec = recover_artifact_hive(&art, &hive);

        assert_eq!(rec.incomplete_reason(), Some(REASON_DIRTY_UNRECOVERED));
        let mut md = json!({});
        rec.stamp(&mut md);
        assert_eq!(md["hive_dirty"], true);
        assert_eq!(md["logs_replayed"], false);
        assert_eq!(md["content_incomplete"], true);
        assert_eq!(md["content_incomplete_reason"], REASON_DIRTY_UNRECOVERED);
    }

    #[test]
    fn a_child_record_carries_the_hives_recovery_state_with_it() {
        let art = artifact_with("SYSTEM", Some(HiveWithLogs::new(primary_hive(9, 8))));
        let hive = primary_hive(9, 8);
        let rec = recover_artifact_hive(&art, &hive);

        let stamp = rec.child_stamp();
        assert_eq!(stamp["recovered"], false);
        assert_eq!(stamp["hive_dirty"], true);
        assert_eq!(stamp["reason"], "no_logs_found");
        assert_eq!(stamp["incomplete_reason"], REASON_DIRTY_UNRECOVERED);
    }

    #[test]
    fn the_changed_key_list_is_omitted_rather_than_stamped_empty() {
        // An empty list would assert that the replay changed nothing. Nothing
        // computed the diff, so the record says exactly that instead.
        let prov = {
            let hive = primary_hive(4, 4);
            let (_, p) = recover_hive(&hive, None, None);
            p
        };
        let mut md = json!({});
        stamp_replay_provenance(&mut md, &prov);
        assert_eq!(md["replay_changed_keys_computed"], false);
        assert!(md.get("replay_changed_keys").is_none());
    }

    #[test]
    fn stamping_a_non_object_metadata_value_is_a_no_op_rather_than_a_panic() {
        let hive = primary_hive(4, 4);
        let (_, prov) = recover_hive(&hive, None, None);
        let mut md = json!("not an object");
        stamp_replay_provenance(&mut md, &prov);
        assert_eq!(md, json!("not an object"));
    }

    #[test]
    fn an_artifact_with_no_data_source_and_no_path_discovers_nothing() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "SYSTEM" }),
        );
        let logs = discover_logs(&art);
        assert!(logs.log1.is_none() && logs.log2.is_none());
        assert!(logs.names.is_empty());
    }
}
