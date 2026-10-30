#![forbid(unsafe_code)]
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    file_detection::{try_detect_file_type, DetectedFileType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_hive::KeyNode;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use tracing::{debug, info, warn};

pub mod bam;
pub mod devprops;
mod installed;
pub mod mounted;
pub mod mru;
pub mod muicache;
pub mod netinterfaces;
pub mod networklist;
pub mod recovered;
mod reglog;
pub mod resident;
pub mod sam;
pub mod security;
pub mod txlog;
pub mod userassist;
pub mod winsearch;

#[cfg(test)]
mod bam_tests;
#[cfg(test)]
mod devprops_tests;
#[cfg(test)]
mod mounted_tests;
#[cfg(test)]
mod mru_tests;
#[cfg(test)]
mod muicache_tests;
#[cfg(test)]
mod netinterfaces_tests;
#[cfg(test)]
#[path = "networklist_tests.rs"]
mod networklist_tests;
#[cfg(test)]
mod real_hive_tests;
#[cfg(test)]
mod recovered_tests;
#[cfg(test)]
mod resident_tests;
#[cfg(test)]
mod sam_tests;
#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod userassist_tests;
#[cfg(test)]
mod value_bytes_tests;
#[cfg(test)]
mod winsearch_tests;

pub struct RegistryParser;

impl ForensicsModule for RegistryParser {
    fn id(&self) -> &str {
        "plugin.windows.registry_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::RawEvidence,
            ArtifactType::SystemArtifact,
            // Read only when it is a shadow-copy prior version (HUNT-277);
            // any other parsed record returns before its data is touched.
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_hive(a))
    }
}

impl RegistryParser {
    fn parse_hive(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let mut produced_artifacts = Vec::new();

        // Check if data source exists - if not, skip silently
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()), // No data source, skip
        };

        // Use content-based detection instead of filename
        // An unreadable header is "could not look", not "not a hive" (CR-047).
        let detected_type =
            try_detect_file_type(data_source.as_ref()).map_err(ModuleError::IoError)?;

        if detected_type != DetectedFileType::RegistryHive {
            // Not a registry hive, skip silently
            return Ok(Vec::new());
        }

        let name = seance_core::shadow_copy::original_name(artifact)
            .unwrap_or("Unknown")
            .to_uppercase();
        let source_path = artifact
            .metadata
            .get("path")
            .or_else(|| artifact.metadata.get("source_path"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let origin = HiveOrigin { source_path };

        info!(
            "Detected Registry hive via content analysis: {} (ID: {})",
            name, artifact.id
        );

        // 2. Read data into buffer (the hive reader borrows an in-memory slice).
        // Cap the load: registry hives are MB-scale, so a huge/mis-detected file
        // must not be pulled into RAM unbounded and OOM the worker.
        const MAX_HIVE_BYTES: u64 = 512 * 1024 * 1024;
        let declared = data_source.size();
        let buffer = seance_core::io::read_capped(data_source.as_ref(), MAX_HIVE_BYTES);
        // What came back against what the source declared. The reader parses the
        // cells it can reach out of a prefix and reports no error, so a hive
        // truncated by the cap or by a short read yields a key/value set that is
        // a SUBSET of the hive's, presented as the whole of it. The key-write
        // scan caps are already stamped; this is the outer buffer (B3-016).
        let staged_short = if (buffer.len() as u64) >= declared {
            None
        } else if declared > MAX_HIVE_BYTES {
            Some(seance_core::io::IncompleteReason::CapReached)
        } else {
            Some(seance_core::io::IncompleteReason::ShortRead)
        };

        // 2b. Suppress standalone parsing of transaction-log files. `.LOG1`/`.LOG2`
        // share the `regf` base-block magic, so content detection classifies them
        // as hives. Parsing a log as a hive yields a junk/empty RegistryHive
        // record. Gate on the base-block file type (1/2 = legacy log, 6 = new log).
        if txlog::is_transaction_log(&buffer) {
            debug!(
                "Skipping registry transaction-log file parsed as a hive: {} (ID: {})",
                name, artifact.id
            );
            return Ok(Vec::new());
        }

        // 2c. Transaction-log replay: if the hive is dirty and its `.LOG1`/`.LOG2`
        // logs are reachable, replay the pending dirty pages into an in-memory
        // copy BEFORE parsing, so extraction reflects the recovered state. Clean
        // hives short-circuit to a zero-copy borrow. Fail-closed: an unverifiable
        // log entry is never applied; the outcome is stamped into provenance.
        let recovery = txlog::recover_artifact_hive(artifact, &buffer);

        // 3. Parse the Hive with panic protection
        // A hive parser can panic on corrupted hives (e.g., arithmetic overflow
        // in corrupt_sub_key_list.hiv). We use catch_unwind to gracefully handle these.
        let case_id = artifact.case_id;
        let artifact_id = artifact.id;
        let name_clone = name.clone();
        let recovered_bytes = recovery.hive();

        let result = catch_unwind(AssertUnwindSafe(|| {
            process_hive_inner(
                recovered_bytes,
                case_id,
                artifact_id,
                &name_clone,
                &recovery,
                &origin,
            )
        }));

        match result {
            Ok(Ok((hive_artifact, timeline_events))) => {
                produced_artifacts.push(hive_artifact);
                produced_artifacts.extend(timeline_events);
            }
            Ok(Err(e)) => {
                warn!(
                    "Failed to parse registry hive '{}' (artifact ID: {}): {}",
                    name, artifact_id, e
                );
                // A hive we could not stage in full and then could not parse is
                // not an absent hive. Say which it was, or "unreadable past
                // byte N" and "no such keys" render identically.
                let mut out = Vec::new();
                out.push(record_parse_failure(
                    case_id,
                    artifact_id,
                    &name,
                    &e,
                    &recovery.provenance,
                ));
                stamp_staging_shortfall(
                    staged_short,
                    case_id,
                    artifact_id,
                    &name,
                    declared,
                    buffer.len() as u64,
                    &mut out,
                );
                return Ok(out);
            }
            Err(panic_info) => {
                // the hive reader panicked (e.g., on corrupted hive)
                let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                warn!(
                    "Registry parser caught panic processing hive '{}' (artifact ID: {}): {}. Skipping corrupted hive.",
                    name, artifact_id, panic_msg
                );
                let mut out = Vec::new();
                out.push(record_parse_failure(
                    case_id,
                    artifact_id,
                    &name,
                    &format!("the hive reader panicked: {panic_msg}"),
                    &recovery.provenance,
                ));
                stamp_staging_shortfall(
                    staged_short,
                    case_id,
                    artifact_id,
                    &name,
                    declared,
                    buffer.len() as u64,
                    &mut out,
                );
                return Ok(out);
            }
        }

        stamp_staging_shortfall(
            staged_short,
            case_id,
            artifact_id,
            &name,
            declared,
            buffer.len() as u64,
            &mut produced_artifacts,
        );

        Ok(produced_artifacts)
    }
}

/// Put a hive this build could not parse **on the record**.
///
/// Content detection said the file is a registry hive; the reader then refused
/// it. Before this existed, that combination produced an empty artifact list and
/// a `debug!` line: the case held the file and nothing else, so the screens that
/// read a machine's name, its installed software, its USB history or its last
/// logon rendered blank — identical to a machine that had none of those things.
/// A silent absence is the failure class this product treats as severe, and this
/// is the one that hid it on every live-acquired image (HUNT-053).
///
/// The marker carries the reader's own error and the replay provenance, because
/// "dirty, and the logs could not bridge the gap" and "the header is corrupt"
/// call for different follow-up and must never render the same.
fn record_parse_failure(
    case_id: uuid::Uuid,
    parent_artifact_id: uuid::Uuid,
    name: &str,
    error: &str,
    prov: &txlog::ReplayProvenance,
) -> Artifact {
    let detail = format!(
        "hive '{name}' was detected but could not be parsed: {error}. No key, value or \
         timestamp from this hive is in the case, so this hive's silence is not evidence \
         of absence."
    );
    let mut meta = json!({
        "type": "RegistryHiveUnparsed",
        "subtype": "parse_failed",
        "status": "HiveNotParsed",
        "hive_type": name,
        "parse_error": error,
        "inventory_incomplete": true,
        "inventory_incomplete_reason":
            seance_core::io::IncompleteReason::UnresolvedStructure.as_str(),
        "inventory_incomplete_detail": detail,
        "content_incomplete": true,
        "content_incomplete_reason":
            seance_core::io::IncompleteReason::UnresolvedStructure.as_str(),
        "incomplete_detail": detail,
        "content_incomplete_detail": detail,
        "detail": detail,
        "name": format!("{name}: hive not parsed — {error}"),
    });
    // The same replay keys every other registry record carries, so an examiner
    // can see whether the logs were the reason.
    txlog::stamp_replay_provenance(&mut meta, prov);
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta)
        .with_parent(parent_artifact_id)
        .with_subtype("parse_failed")
}

/// Record on the hive record that the key walk stopped at the recursion depth
/// limit, in the vocabulary the API and export honesty paths read.
///
/// A no-op when the walk completed, so an unmarked `RegistryHive` record still
/// means its `all_keys` / `all_values` are everything the hive holds. What an
/// examiner learns: whether a key's absence from the inventory is evidence. A
/// walk cut short at depth makes "not present" unsafe to assert.
fn stamp_inventory_cap(hive_metadata: &mut serde_json::Value, ctx: &TraversalContext) {
    let Some(map) = hive_metadata.as_object_mut() else {
        return;
    };
    // Always stated, so "the walk lost nothing" and "nobody counted" cannot
    // render identically.
    map.insert("walk_subkey_errors".to_string(), json!(ctx.subkey_errors));
    map.insert("walk_value_errors".to_string(), json!(ctx.value_errors));
    let undecodable = ctx.subkey_errors > 0 || ctx.value_errors > 0;
    if !ctx.depth_capped && !undecodable {
        return;
    }
    // A depth cap and a node the hive parser refused call for different
    // follow-up, so they never share a reason.
    let reason = if ctx.depth_capped {
        seance_core::io::IncompleteReason::CapReached
    } else {
        seance_core::io::IncompleteReason::UnresolvedStructure
    };
    map.insert("inventory_incomplete".to_string(), json!(true));
    map.insert(
        "inventory_incomplete_reason".to_string(),
        json!(reason.as_str()),
    );
    map.insert("content_incomplete".to_string(), json!(true));
    map.insert(
        "content_incomplete_reason".to_string(),
        json!(reason.as_str()),
    );
    let detail = if ctx.depth_capped {
        "the key walk stopped at the recursion depth limit; keys and values below that \
         point are absent from this record but not from the hive"
            .to_string()
    } else {
        format!(
            "{} subkeys and {} values could not be read out of this hive; the keys and \
             settings they hold are absent from this record but not from the hive",
            ctx.subkey_errors, ctx.value_errors
        )
    };
    map.insert("incomplete_detail".to_string(), json!(detail));
}

/// Carry an outer staging shortfall onto everything parsed out of the hive.
///
/// `reason` is `None` when the whole hive was staged, and this is then a no-op,
/// so an unmarked registry record still means the parse saw the entire file.
///
/// When the hive was NOT staged whole, two things happen, mirroring the shared
/// SQLite spill contract (`TempDb::stamp_incompleteness`) so the API and export
/// honesty paths — which key on `content_incomplete` — read the same vocabulary
/// from every producer:
///
/// 1. every artifact gains `content_incomplete` plus
///    `content_incomplete_reason`, so a key, value, USB device or typed URL
///    recovered from a partial hive carries that fact wherever it is exported;
///    and
/// 2. one `parse_incomplete` marker is appended, which is what an examiner sees
///    when the truncation cut so deep that nothing parsed at all.
///
/// What an examiner learns: whether the keys shown are all the hive holds. A
/// missing `Run` entry or USB serial past the staged bytes would otherwise read
/// as a device that was never attached.
fn stamp_staging_shortfall(
    reason: Option<seance_core::io::IncompleteReason>,
    case_id: uuid::Uuid,
    parent_artifact_id: uuid::Uuid,
    name: &str,
    declared_bytes: u64,
    staged_bytes: u64,
    artifacts: &mut Vec<Artifact>,
) {
    let Some(reason) = reason else {
        return;
    };
    for artifact in artifacts.iter_mut() {
        if let Some(map) = artifact.metadata.as_object_mut() {
            map.insert("content_incomplete".to_string(), json!(true));
            map.insert(
                "content_incomplete_reason".to_string(),
                json!(reason.as_str()),
            );
        }
    }
    let detail = format!(
        "hive '{name}' was not staged in full ({}): {staged_bytes} of {declared_bytes} bytes \
         were read, so keys and values past that point were never parsed",
        reason.as_str()
    );
    let mut meta = serde_json::Map::new();
    meta.insert("type".to_string(), json!("RegistryHiveIncomplete"));
    meta.insert("subtype".to_string(), json!("parse_incomplete"));
    meta.insert("status".to_string(), json!("HiveNotStagedInFull"));
    meta.insert("hive_type".to_string(), json!(name));
    meta.insert("content_incomplete".to_string(), json!(true));
    meta.insert(
        "content_incomplete_reason".to_string(),
        json!(reason.as_str()),
    );
    meta.insert("declared_bytes".to_string(), json!(declared_bytes));
    meta.insert("staged_bytes".to_string(), json!(staged_bytes));
    // The key the UI renders from; `detail` alone is read by nothing. Without
    // it the examiner saw "hive not staged in full" and never the declared and
    // staged byte counts that say how much of it is missing.
    meta.insert(
        "content_incomplete_detail".to_string(),
        json!(detail.clone()),
    );
    meta.insert("detail".to_string(), json!(detail.clone()));
    meta.insert(
        "name".to_string(),
        json!(format!("{name}: partial hive — {detail}")),
    );
    artifacts.push(
        Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::Value::Object(meta),
        )
        .with_parent(parent_artifact_id)
        .with_subtype("parse_incomplete"),
    );
}

/// Layered-key bits seen while walking one hive (§5.9; `seance_hive::layered`).
#[derive(Default)]
struct LayeredKeyCounts {
    tombstone: u64,
    supersede_local: u64,
    supersede_tree: u64,
}

impl LayeredKeyCounts {
    /// Count one key and name what its bits say, or `None` for an ordinary key
    /// (and for any hive below minor version 6, where the byte is spare).
    fn observe(&mut self, key: &KeyNode<'_>) -> Option<&'static str> {
        use seance_hive::layered::LayerSemantics;
        match key.layered_key_bits()?.semantics {
            LayerSemantics::None => None,
            LayerSemantics::Tombstone => {
                self.tombstone += 1;
                Some("tombstone")
            }
            LayerSemantics::SupersedeLocal => {
                self.supersede_local += 1;
                Some("supersede_local")
            }
            LayerSemantics::SupersedeTree => {
                self.supersede_tree += 1;
                Some("supersede_tree")
            }
        }
    }

    fn any(&self) -> bool {
        self.tombstone + self.supersede_local + self.supersede_tree > 0
    }

    /// Stamp what the hive is onto its record. The version is always recorded;
    /// the claim "this is a differencing hive" is made only when keys carry the
    /// bits, because the version alone does not make a hive one.
    fn stamp(&self, meta: &mut serde_json::Value, minor_version: u32) {
        meta["hive_minor_version"] = json!(minor_version);
        if !self.any() {
            return;
        }
        meta["differencing_hive"] = json!(true);
        meta["layered_keys"] = json!({
            "tombstone": self.tombstone,
            "supersede_local": self.supersede_local,
            "supersede_tree": self.supersede_tree,
        });
        meta["differencing_statement"] = json!(
            "This hive carries layered-key bits: it is one layer's differencing hive, a list \
             of what that layer changed, not a registry. A tombstoned key was DELETED at this \
             layer and is not live; a key this hive does not list says nothing about whether \
             the container had it. What the container saw is the merge of the base hive and \
             every layer between, which this record is not."
        );
    }
}

/// Context for recursive registry traversal - groups mutable accumulators
struct TraversalContext {
    all_keys: Vec<serde_json::Value>,
    all_values: Vec<serde_json::Value>,
    timeline_events: Vec<Artifact>,
    /// USB mass-storage devices found under USBSTOR (one per device instance).
    usb_devices: Vec<serde_json::Value>,
    /// Set when the recursion depth limit stopped the walk. The key/value
    /// inventory is then a subset of the hive, and saying so is the difference
    /// between "no such key" and "we stopped descending".
    depth_capped: bool,
    /// Keys carrying layered-key bits (a differencing hive's changes), counted by
    /// meaning: tombstone, supersede-local, supersede-tree (§5.9).
    layered: LayeredKeyCounts,
    /// Subkey nodes the hive parser refused, or whose name would not decode.
    /// Each one is a key — and its whole subtree — missing from the inventory.
    subkey_errors: u64,
    /// Key security, accumulated as the walk passes each key (§2.5).
    security: security::SecurityInventory,
    /// Raw value bytes for the registry-resident artifacts, captured only from
    /// anchored keys (§2.5). The walk's own `all_values` publishes a rendering,
    /// and a 72-byte UserAssist entry cannot be decoded from a hex string.
    resident: resident::ResidentCapture,
    /// Value nodes the hive parser refused. Each one is a setting missing from
    /// the key it belongs to.
    value_errors: u64,
    /// What the hive has published of its values' stored bytes (`HUNT-159`).
    value_bytes: ValueBytesBudget,
}

/// Parse a USBSTOR device-instance key path into `(device_class, serial)`.
///
/// Instance keys look like
/// `...\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\<serial>&0`. Returns
/// None for the USBSTOR root, a class key, or anything deeper than the
/// instance level.
///
/// **The `Enum\` anchor is the whole point.** A device that was actually
/// attached is enrolled under `ControlSet00N\Enum\USBSTOR`. Several other keys
/// on a stock Windows install also spell `USBSTOR` two levels deep and describe
/// no device at all: `ControlSet00N\Control\usbstor\<VVVVPPPP>\DeviceHackFlags`
/// is the driver's per-chipset quirk list, shipped with the OS, and SOFTWARE
/// mirrors it under `Setup\PnpResources`. Matching `\USBSTOR\` anywhere read
/// those as attached devices: the DFIR Madness domain controller, which has no
/// `Enum\USBSTOR` key at all and never had a USB disk in it, reported five —
/// two of them Apple — with `DeviceHackFlags` as the serial number (HUNT-056).
/// A device fabricated onto a machine's USB history is evidence of an event
/// that did not happen.
fn parse_usbstor_instance(key_path: &str) -> Option<(String, String)> {
    // ASCII-only fold so the byte index stays valid for slicing the original
    // path (a Unicode uppercase can change byte length and misalign the slice).
    let upper = key_path.to_ascii_uppercase();
    let marker = "\\ENUM\\USBSTOR\\";
    let idx = upper.find(marker)?;
    let rest = &key_path[idx + marker.len()..];
    let mut parts = rest.split('\\');
    let class = parts.next()?.trim();
    let serial = parts.next()?.trim();
    // Exactly the instance level: class\serial with nothing deeper.
    if parts.next().is_some() || class.is_empty() || serial.is_empty() {
        return None;
    }
    Some((class.to_string(), serial.to_string()))
}

/// Split a USBSTOR device class into (vendor, product, revision).
fn parse_device_class(class: &str) -> (Option<String>, Option<String>, Option<String>) {
    let (mut ven, mut prod, mut rev) = (None, None, None);
    for seg in class.split('&') {
        if let Some(v) = seg.strip_prefix("Ven_") {
            ven = Some(v.replace('_', " ").trim().to_string());
        } else if let Some(v) = seg.strip_prefix("Prod_") {
            prod = Some(v.replace('_', " ").trim().to_string());
        } else if let Some(v) = seg.strip_prefix("Rev_") {
            rev = Some(v.trim().to_string());
        }
    }
    (ven, prod, rev)
}

/// Normalise IE/Edge **TypedURLs** from a hive's already-extracted values into
/// browser-history-shaped records. `...\Internet Explorer\TypedURLs` holds
/// `url1..urlN` (addresses the user typed into the address bar); the sibling
/// `TypedURLsTime` key holds a FILETIME per matching name. Pure over the value
/// list so it is testable without a hive.
///
/// `replay` is the hive's compact recovery stamp
/// ([`txlog::HiveRecovery::child_stamp`]), copied onto every record: a URL read
/// out of a dirty, unrecovered hive must not look like one read from the state
/// at acquisition once it is far from its hive in a list or an export.
fn build_typed_url_records(
    all_values: &[serde_json::Value],
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    replay: &serde_json::Value,
) -> Vec<Artifact> {
    use std::collections::BTreeMap;
    let ends_ci = |p: &str, suffix: &str| p.to_ascii_lowercase().ends_with(suffix);

    let mut urls: BTreeMap<u32, String> = BTreeMap::new();
    let mut times: BTreeMap<u32, i64> = BTreeMap::new();
    for v in all_values {
        let (Some(kp), Some(vn), Some(vd)) = (
            v.get("key_path").and_then(|x| x.as_str()),
            v.get("value_name").and_then(|x| x.as_str()),
            v.get("value_data").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        let Some(idx) = vn
            .to_ascii_lowercase()
            .strip_prefix("url")
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if ends_ci(kp, "internet explorer\\typedurls") {
            if !vd.is_empty() {
                urls.insert(idx, vd.to_string());
            }
        } else if ends_ci(kp, "internet explorer\\typedurlstime") {
            if let Some(t) = filetime_hex_to_unix(vd) {
                times.insert(idx, t);
            }
        }
    }

    urls.into_iter()
        .map(|(idx, url)| {
            let mut m = serde_json::Map::new();
            m.insert("type".into(), json!("TypedUrl"));
            m.insert("subtype".into(), json!("browser_typed_url"));
            m.insert("browser".into(), json!("Internet Explorer / Edge"));
            m.insert("url".into(), json!(url));
            m.insert("typed_order".into(), json!(idx));
            if let Some(t) = times.get(&idx) {
                m.insert("last_typed_time".into(), json!(t));
            }
            m.insert("name".into(), json!(format!("Typed URL: {url}")));
            // The hive this came from: recovered, stale, or clean.
            m.insert("replay".into(), replay.clone());
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::Value::Object(m),
            )
            .with_parent(parent_id)
        })
        .collect()
}

/// Decode a whitespace-separated hex FILETIME (8 bytes, little-endian) to Unix
/// seconds. `None` for a zero or truncated value.
fn filetime_hex_to_unix(hex: &str) -> Option<i64> {
    let bytes: Vec<u8> = hex
        .split_whitespace()
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();
    if bytes.len() < 8 {
        return None;
    }
    let ft = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    // Delegates the epoch math AND the zero/pre-1970 rejection, so a corrupt
    // cell can no longer yield a negative/1601-era Unix time.
    seance_core::time::filetime_to_unix_secs(ft)
}

/// Inner function to process a registry hive. Separated to allow catch_unwind wrapping.
/// Where a hive came from, as far as its path says.
///
/// A Windows volume normally holds several copies of the same hive: the live
/// one under `config\`, the `RegBack` copy the scheduled task refreshes, and
/// whatever volume-shadow snapshots reproduce. They are the same machine at
/// different times, and a consumer weighing them as independent witnesses —
/// as System Info did, refusing a last-shutdown time because the RegBack copy
/// disagreed with the live hive (HUNT-062) — is wrong in a way that hides the
/// answer. The role is stated on the record so that consumer can tell them
/// apart.
struct HiveOrigin {
    source_path: Option<String>,
}

impl HiveOrigin {
    /// `live`, `regback`, or `unknown` when there is no path to judge by.
    fn role(&self) -> &'static str {
        let Some(path) = self.source_path.as_deref() else {
            return "unknown";
        };
        let lower = path.to_ascii_lowercase().replace('/', "\\");
        if lower.contains("\\config\\regback\\") {
            "regback"
        } else {
            "live"
        }
    }
}

/// `Select\Current` — the control set the machine booted — out of the walk's
/// rendered values.
///
/// The value is a `REG_DWORD`, which [`display_value_data`] renders as
/// `0x00000001 (1)`; the decimal in the parentheses is the number. A bare
/// decimal is accepted as well. Reading only the bare form made every real
/// `SYSTEM` hive report no current control set (`BAM-1`).
pub(crate) fn select_current(all_values: &[serde_json::Value]) -> Option<u32> {
    all_values.iter().find_map(|v| {
        let key = v.get("key_path")?.as_str()?;
        let name = v.get("value_name")?.as_str()?;
        let tail = key.rsplit('\\').next().unwrap_or("");
        if !(tail.eq_ignore_ascii_case("Select") && name.eq_ignore_ascii_case("Current")) {
            return None;
        }
        let rendered = v.get("value_data")?.as_str()?.trim();
        rendered.parse::<u32>().ok().or_else(|| {
            rendered
                .rsplit_once('(')
                .and_then(|(_, rest)| rest.strip_suffix(')'))
                .and_then(|n| n.trim().parse::<u32>().ok())
        })
    })
}

fn process_hive_inner(
    buffer: &[u8],
    case_id: uuid::Uuid,
    parent_artifact_id: uuid::Uuid,
    name: &str,
    recovery: &txlog::HiveRecovery<'_>,
    origin: &HiveOrigin,
) -> Result<(Artifact, Vec<Artifact>), String> {
    let prov = &recovery.provenance;
    // One door for every hive this product opens (`seance_hive_util::open_hive`):
    // it guards the upstream signature panic (HUNT-046) and, crucially here,
    // accepts a hive whose sequence numbers do not match. A hive lifted off a
    // running machine is dirty by default, and refusing it lost every key in it
    // (HUNT-053). `recovery` above already establishes and stamps whether the
    // logs put it back to its captured state. A hive shorter than its header
    // declares is opened too, and the shortfall is stamped below (HUNT-061).
    let opened = seance_hive_util::open_hive_reporting(buffer)?;
    let short_by = opened.short_by;
    let hive = opened.hive;

    let root_key_node = hive
        .root_key_node()
        .map_err(|e| format!("Failed to get root key: {}", e))?;

    let root_key_name = root_key_node
        .name()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    info!(
        "Registry hive {}: Starting recursive traversal from root key '{}'",
        name, root_key_name
    );

    // Recursively traverse and extract all keys/values
    let mut ctx = TraversalContext {
        all_keys: Vec::new(),
        all_values: Vec::new(),
        timeline_events: Vec::new(),
        usb_devices: Vec::new(),
        layered: LayeredKeyCounts::default(),
        depth_capped: false,
        subkey_errors: 0,
        value_errors: 0,
        security: security::SecurityInventory::default(),
        resident: resident::ResidentCapture::default(),
        value_bytes: ValueBytesBudget::with_limit(MAX_VALUE_BYTES_PER_HIVE),
    };

    traverse_registry_key(&root_key_node, &root_key_name, &mut ctx, 0);

    // Timeline events for key writes come from a direct, bounds-checked scan
    // of the raw hive cells rather than from the walk above. The walk now
    // carries each key's timestamp onto its record, but the scan still earns
    // its place: it reaches cells the walk cannot — keys whose parent chain is
    // broken, and cells outside the index — and it records its own coverage.
    // This does not alter the ParsedRecord output above.
    // Take the events out but keep the scan, because the coverage it records —
    // whether a cap stopped it, and which — is stamped onto the hive artifact
    // below. Moving the whole scan here would leave the timeline present and
    // its completeness unstated.
    let mut key_scan = extract_key_write_events(buffer, case_id, parent_artifact_id);
    ctx.timeline_events = std::mem::take(&mut key_scan.events);

    // What the free space holds (`ROADMAP` §5.9): keys and values a deletion
    // marked free and did not overwrite. Published below as their own record
    // types, never merged into `all_keys`/`all_values`, and summarised on the
    // hive record with every ceiling and its number.
    let recovered_scan = recovered::recover_unallocated_cells(&hive);

    info!(
        "Registry hive {}: Extracted {} keys, {} values, {} timeline events",
        name,
        ctx.all_keys.len(),
        ctx.all_values.len(),
        ctx.timeline_events.len()
    );

    // Create hive metadata artifact
    let mut hive_metadata = json!({
        "type": "RegistryHive",
        "hive_type": name,
        "root_key_name": root_key_name,
        "total_keys": ctx.all_keys.len(),
        "total_values": ctx.all_values.len(),
        "all_keys": ctx.all_keys,
        "all_values": ctx.all_values,
        // Key-write timeline coverage. A SOFTWARE or SYSTEM hive can hold more
        // keys than the scan caps allow; without these an examiner reading the
        // timeline would take "no write after date X" as fact when the scan
        // simply stopped counting.
        "key_timeline_complete": key_scan.complete(),
        "key_timeline_cap_reason": key_scan.cap_reason(),
        "recovered_cells": recovered_scan.summary(),
        // Whether the key/value walk itself reached every key. A hive with a
        // circular or pathologically deep subtree stops at the recursion limit;
        // without this the keys below it read as keys the hive never had.
        "key_inventory_complete": !ctx.depth_capped
            && ctx.subkey_errors == 0
            && ctx.value_errors == 0,
    });
    ctx.layered.stamp(&mut hive_metadata, hive.minor_version());
    // The distinct descriptor population, walked from the hive's own `sk` ring
    // rather than from the keys. A descriptor carried by exactly one key is
    // what a widened ACL looks like, and that is not expressible from a
    // per-key copy of the ACL.
    let descriptors = ctx.security.resolve(&hive);
    if let Some(map) = hive_metadata.as_object_mut() {
        map.insert(
            "key_security".to_string(),
            ctx.security.to_json(&descriptors),
        );
        map.insert(
            "security_descriptors".to_string(),
            json!(descriptors.iter().map(|d| d.to_json()).collect::<Vec<_>>()),
        );
    }
    // Which control set the machine booted, from `Select\Current`. Without it
    // this build cannot say, and BAM's records say `is_current_control_set:
    // false` rather than guessing -- two copies of a machine's state are one
    // machine, and the consumer must see which copy it is reading (HUNT-062).
    let current_control_set = select_current(&ctx.all_values);

    // The registry-resident artifacts, decoded from the captured bytes (§2.5).
    let mut resident_records: Vec<serde_json::Value> = userassist::emit(&ctx.resident);
    // The control sets this hive holds, so BAM can state the absence of its key
    // per control set rather than falling silent.
    let control_sets: Vec<String> = {
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for key in &ctx.all_keys {
            if let Some(path) = key.get("key_path").and_then(|v| v.as_str()) {
                if let Some(seg) = path.split('\\').nth(1) {
                    let lower = seg.to_ascii_lowercase();
                    if lower.starts_with("controlset") || lower == "currentcontrolset" {
                        seen.insert(seg.to_string());
                    }
                }
            }
        }
        seen.into_iter().collect()
    };
    resident_records.extend(muicache::emit(&ctx.resident));
    resident_records.extend(mru::emit(&ctx.resident));
    resident_records.extend(netinterfaces::emit(&ctx.resident));
    resident_records.extend(networklist::emit(&ctx.resident));
    resident_records.extend(mounted::emit(&ctx.resident));
    resident_records.extend(winsearch::emit(&ctx.resident, &control_sets));
    resident_records.extend(sam::emit(&ctx.resident));
    resident_records.extend(bam::emit(&ctx.resident, current_control_set, &control_sets));
    if let Some(map) = hive_metadata.as_object_mut() {
        // A capture that stopped at a ceiling must not have its records read as
        // the whole population.
        map.insert(
            "resident_capture_complete".to_string(),
            json!(ctx.resident.complete()),
        );
        if let Some(why) = ctx.resident.capped {
            map.insert("resident_capture_cap_reason".to_string(), json!(why));
            map.insert("content_incomplete".to_string(), json!(true));
            map.insert(
                "content_incomplete_reason".to_string(),
                json!(seance_core::io::IncompleteReason::CapReached.as_str()),
            );
        }
    }
    stamp_inventory_cap(&mut hive_metadata, &ctx);
    ctx.value_bytes.stamp(&mut hive_metadata);
    if let Some(map) = hive_metadata.as_object_mut() {
        map.insert("source_path".to_string(), json!(origin.source_path));
        map.insert("hive_role".to_string(), json!(origin.role()));
    }
    // A hive whose file holds fewer hive-bin bytes than its base block
    // declares was cut short — a shadow copy taken while it grew, or a short
    // acquisition. Every cell read is real; the cells past the cut are not in
    // this record and were not in the file, and the record says so in the
    // vocabulary the API and export honesty paths read (HUNT-061).
    if let Some((declared, present)) = short_by {
        if let Some(map) = hive_metadata.as_object_mut() {
            map.insert("hive_declared_data_bytes".to_string(), json!(declared));
            map.insert("hive_present_data_bytes".to_string(), json!(present));
            map.insert("content_incomplete".to_string(), json!(true));
            map.insert(
                "content_incomplete_reason".to_string(),
                json!(seance_core::io::IncompleteReason::ShortRead.as_str()),
            );
            map.insert(
                "content_incomplete_detail".to_string(),
                json!(format!(
                    "the hive's base block declares {declared} bytes of hive bins and the file \
                     holds {present}; keys and values in the missing {} bytes were never in this \
                     copy of the hive",
                    declared.saturating_sub(present)
                )),
            );
        }
    }
    // Additive transaction-log replay provenance (§3.6). Additive metadata keys
    // on the same record — no schema break, no migration. The examiner (and the
    // registry-explorer API/UI) can now state whether the parsed state is the
    // on-disk (pre-replay) or recovered (post-replay) hive, and why.
    recovery.stamp(&mut hive_metadata);
    let hive_artifact = Artifact::new(case_id, ArtifactType::ParsedRecord, None, hive_metadata)
        .with_parent(parent_artifact_id);

    // Emit one UsbDevice ParsedRecord per USBSTOR device instance found. These
    // ride out alongside the timeline events as extra produced artifacts.
    let mut extra_artifacts = ctx.timeline_events;

    // One TimelineEvent per replayed hive: a real, citable "hive flushed" moment,
    // gated on a valid post-replay last-written FILETIME (omit for the 1601/unset
    // sentinel so a corrupt field never yields a fabricated event).
    if prov.replayed {
        if let Some(ts) = prov.last_written_after.clone() {
            let ies = if prov.entries_applied == 1 {
                "y"
            } else {
                "ies"
            };
            let event = Artifact::new(
                case_id,
                ArtifactType::TimelineEvent,
                None,
                json!({
                    "timestamp": ts,
                    "timestamp_desc": "Registry Hive Flushed (log replay recovered)",
                    "source_module": "plugin.windows.registry_parser",
                    "short_desc": format!(
                        "Recovered {} from {} log entr{}",
                        name, prov.entries_applied, ies
                    ),
                    "full_details": json!({
                        "log_files": prov.log_files,
                        "log_format": prov.log_format,
                        "dirty_pages": prov.pages_applied,
                        "sequence_range": [prov.applied_start_seq, prov.applied_end_seq],
                    })
                    .to_string(),
                }),
            )
            .with_parent(parent_artifact_id);
            extra_artifacts.push(event);
        }
    }

    // Every record derived from this hive carries the hive's recovery state, so
    // a USB device or typed URL read out of a stale (dirty, unrecovered) hive is
    // never presented like one read from the state at acquisition.
    let child_replay = recovery.child_stamp();

    // The recovered keys and values, each a distinct type from its live
    // counterpart, with the hive's recovery state on every one.
    extra_artifacts.extend(recovered::emit(
        &recovered_scan,
        &key_scan.live_cells,
        name,
        case_id,
        parent_artifact_id,
        &child_replay,
    ));

    // Normalise IE/Edge TypedURLs into browser-history-shaped records.
    extra_artifacts.extend(build_typed_url_records(
        &ctx.all_values,
        case_id,
        parent_artifact_id,
        &child_replay,
    ));
    // When each device was installed and, on Windows 8 and later, last
    // connected -- from its Properties subtree (§2.6). Until this, a UsbDevice
    // record carried no timestamp of any kind.
    let device_properties = devprops::read(&ctx.resident);
    for dev in ctx.usb_devices {
        if let Some(obj) = dev.as_object() {
            let mut md = serde_json::Map::new();
            md.insert("type".to_string(), json!("UsbDevice"));
            md.insert("hive".to_string(), json!(name));
            md.insert("replay".to_string(), child_replay.clone());
            for (k, v) in obj {
                md.insert(k.clone(), v.clone());
            }
            // Matched on the device-instance key the properties hang off, so a
            // device with no property subtree gets the sentence saying the
            // REGISTRY records no time rather than silence.
            let key_path = obj.get("key_path").and_then(|v| v.as_str()).unwrap_or("");
            let props = device_properties
                .iter()
                .find(|(k, _)| key_path.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.as_slice())
                .unwrap_or(&[]);
            let mut value = serde_json::Value::Object(md);
            devprops::stamp(&mut value, props);
            let md = match value {
                serde_json::Value::Object(m) => m,
                _ => unreachable!("stamp keeps the object it was given"),
            };
            extra_artifacts.push(
                Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    serde_json::Value::Object(md),
                )
                .with_parent(parent_artifact_id),
            );
        }
    }

    // One InstalledProgram per Uninstall subkey (SOFTWARE, its Wow6432Node
    // mirror, and a user hive's Software\...). Reads the hive record for its
    // type, path and any incomplete stamp, and the key-write events already
    // in `extra_artifacts` for each entry's last-write time.
    installed::emit_installed_programs(
        &mut extra_artifacts,
        &ctx.all_keys,
        &ctx.all_values,
        &hive_artifact,
        &child_replay,
    );

    // The registry-resident records (§2.5), each carrying the hive's recovery
    // state for the same reason every other child record does: a program
    // execution read out of a stale hive must never be presented like one read
    // from the state at acquisition.
    for mut record in resident_records {
        if let Some(map) = record.as_object_mut() {
            map.insert("hive".to_string(), json!(name));
            map.insert("replay".to_string(), child_replay.clone());
        }
        // A resident emitter may build a timeline event of its own -- the
        // shell MRU reading raises one "MRU key last written" per dated key
        // (`mru::MruCoverage::timeline_event`). It is an event, so it goes to
        // the case as one; wrapping it as a ParsedRecord whose `type` says
        // TimelineEvent put it where the timeline never looks (HUNT-166).
        if record.get("type").and_then(|v| v.as_str()) == Some("TimelineEvent") {
            extra_artifacts.push(
                Artifact::new(case_id, ArtifactType::TimelineEvent, None, record)
                    .with_parent(parent_artifact_id),
            );
            continue;
        }
        // A UserAssist entry that names a program run, at a known time, is a
        // timeline event. Bookkeeping is not, and neither is an entry whose
        // payload this build could not decode -- there is no time to place it
        // at, and inventing one is the failure this whole module is written
        // against.
        let executed_at = record
            .get("last_executed")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // A BamEntry is an execution by construction -- the emitter already
        // filtered out Version and SequenceNumber -- so it earns an event
        // whenever it carries a time. A UserAssistEntry says for itself.
        let is_execution = record
            .get("is_execution")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| record.get("type").and_then(|v| v.as_str()) == Some("BamEntry"));
        let label = record
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(unnamed)")
            .to_string();
        let record_type = record
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // Each artifact names itself in the timeline, because "last executed"
        // from UserAssist and from BAM are different observations of the same
        // claim and an examiner corroborating one with the other has to be
        // able to tell them apart.
        let (timestamp_desc, source_long) = match record_type.as_str() {
            "BamEntry" => ("Program last executed (BAM)", format!("BAM/DAM ({name})")),
            _ => (
                "Program last executed (UserAssist)",
                format!("UserAssist ({name})"),
            ),
        };
        extra_artifacts.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, record)
                .with_parent(parent_artifact_id),
        );
        if let (true, Some(when)) = (is_execution, executed_at) {
            extra_artifacts.push(
                Artifact::new(
                    case_id,
                    ArtifactType::TimelineEvent,
                    None,
                    json!({
                        "type": "TimelineEvent",
                        "timestamp": when,
                        "timestamp_desc": timestamp_desc,
                        "name": label,
                        "source": "Registry",
                        "source_long": source_long,
                        "replay": child_replay.clone(),
                    }),
                )
                .with_parent(parent_artifact_id),
            );
        }
    }

    Ok((hive_artifact, extra_artifacts))
}

/// Recursively traverse a registry key and extract all subkeys and values
fn traverse_registry_key(
    key_node: &KeyNode<'_>,
    key_path: &str,
    ctx: &mut TraversalContext,
    depth: usize,
) {
    // Limit recursion depth to prevent stack overflow on malformed hives.
    // Stopping is right; stopping SILENTLY is not — the keys below this point
    // are then absent from `all_keys` with nothing to distinguish them from
    // keys the hive never had, so the cut is recorded on the context and
    // stamped onto the hive record.
    const MAX_DEPTH: usize = 100;
    if depth > MAX_DEPTH {
        warn!(
            "Registry traversal depth limit ({}) reached at key '{}' (possible circular reference or malformed hive)",
            MAX_DEPTH, key_path
        );
        ctx.depth_capped = true;
        return;
    }

    // When the key was last written, and how much it holds. Until 2026-09-13
    // the reader kept the NK timestamp private and these three fields were
    // absent, so a key inventory could not distinguish a key written during
    // the incident from one written at install. `seance_hive` exposes them.
    // `last_written` is omitted rather than guessed when the FILETIME is one
    // no clock produced — a zeroed or impossible timestamp is not a date.
    // The subkey index is resolved before the key record is written, because
    // the record has to say when the index root lost a sublist (HIVE-002): the
    // keys under a damaged `ri` list are absent from `all_keys` and are not
    // absent from the hive, and a key that reports fewer subkeys than it
    // declared, with nothing said, reads as a complete one.
    let subkeys_iter = match key_node.subkeys() {
        Some(Ok(sk)) => Some(sk),
        Some(Err(_)) => {
            ctx.subkey_errors += 1;
            None
        }
        None => None,
    };
    let unresolved_sublists: Vec<serde_json::Value> = subkeys_iter
        .as_ref()
        .map(|sk| {
            sk.unresolved_sublists()
                .iter()
                .map(|u| json!({ "offset": u.offset, "error": u.error.to_string() }))
                .collect()
        })
        .unwrap_or_default();

    // How many subkeys the key says it has, and how many its index actually
    // names. The hive can disagree with itself here, and the disagreement is
    // evidence: it is a damaged index, or a deleted key whose parent still
    // counts it. `subkeys_listed` is absent — not zero — when the key declares
    // no subkeys at all, because there is then no index to have counted.
    let declared_subkeys = key_node.subkey_count();
    let listed_subkeys = subkeys_iter.as_ref().map(|sk| sk.listed_len());

    let mut key_data = json!({
        "key_path": key_path,
        "key_name": key_path.rsplit('\\').next().unwrap_or(key_path),
        "depth": depth,
        "last_written": filetime_to_rfc3339(key_node.last_written_filetime()),
        "subkey_count": declared_subkeys,
        "subkeys_listed": listed_subkeys,
        "value_count": key_node.value_count(),
    });
    if let Some(listed) = listed_subkeys {
        if listed != declared_subkeys as usize {
            let map = key_data.as_object_mut().expect("json object");
            map.insert("subkey_count_disagrees_with_index".to_string(), json!(true));
            map.insert(
                "subkey_count_disagreement".to_string(),
                json!(format!(
                    "This key declares {declared_subkeys} subkey(s) and its subkey index \
                     names {listed}. The enumeration below is the index, which is what the \
                     hive can actually be walked to."
                )),
            );
        }
    }
    if !unresolved_sublists.is_empty() {
        ctx.subkey_errors += unresolved_sublists.len() as u64;
        let map = key_data.as_object_mut().expect("json object");
        map.insert("subkeys_incomplete".to_string(), json!(true));
        map.insert(
            "subkeys_incomplete_reason".to_string(),
            json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
        );
        map.insert(
            "subkeys_incomplete_detail".to_string(),
            json!(format!(
                "{} of this key's subkey lists could not be read; the subkeys they name \
                 are absent from this inventory but not from the hive",
                unresolved_sublists.len()
            )),
        );
        map.insert(
            "unresolved_sublists".to_string(),
            json!(unresolved_sublists),
        );
    }
    // Who could change this key. Stamped here rather than decoded here: the
    // descriptor itself is shared -- 117,488 keys over 289 descriptors on the
    // real SOFTWARE hive -- so the decoded ACL is written once into the hive
    // record's descriptor table and this is the join to it (§2.5).
    let key_security = security::KeySecurity::of(key_node);
    security::stamp_key_security(&mut key_data, &key_security);
    ctx.security.observe(&key_security);
    // A differencing hive's key says what its layer did to it. Stated per key,
    // because the same key read in an ordinary hive means something else: a
    // tombstone is a deletion, not a live key.
    if let Some(label) = ctx.layered.observe(key_node) {
        key_data
            .as_object_mut()
            .expect("json object")
            .insert("layer_semantics".to_string(), json!(label));
    }

    ctx.all_keys.push(key_data);

    // USB mass-storage detection: a USBSTOR instance key records a device that
    // was connected. Capture its class/serial now and its FriendlyName below.
    // Which registry-resident family this key belongs to, asked once per key so
    // the value loop below can ask a cheap question instead of matching strings
    // per value. `None` -- which is almost every key -- captures nothing.
    let resident_key = resident::anchor_of(key_path).and_then(|anchor| {
        ctx.resident
            .begin_key(key_path, anchor, key_node.last_written_filetime())
    });

    let usb_instance = parse_usbstor_instance(key_path);
    let mut usb_friendly_name: Option<String> = None;

    // Extract all values from this key. A value node the hive parser refuses is
    // counted, never dropped: it is a setting absent from this key's inventory,
    // and an examiner reading the key would take the absence as fact.
    let values_iter = match key_node.values() {
        Some(Ok(v)) => Some(v),
        Some(Err(_)) => {
            ctx.value_errors += 1;
            None
        }
        None => None,
    };
    if let Some(values_iter) = values_iter {
        for value in values_iter {
            let value = match value {
                Ok(v) => v,
                Err(_) => {
                    ctx.value_errors += 1;
                    continue;
                }
            };
            let value_name = value
                .name()
                .map(|n| n.to_string())
                .unwrap_or_else(|_| "(Default)".to_string());

            // Get value type
            let value_type_str = match value.data_type() {
                Ok(dt) => format!("{:?}", dt), // Use Debug format for enum
                Err(_) => "Unknown".to_string(),
            };

            // Get value data - convert KeyValueData to Vec<u8>. The record's
            // data fields — rendering, stored bytes, multi-string elements —
            // are written once, by `publish_value_data`.
            let mut data_fields = serde_json::Map::new();
            let (value_data_str, raw_data_size) = match value.data() {
                Ok(data) => {
                    match data.into_vec() {
                        Ok(bytes) => {
                            let size = bytes.len();
                            publish_value_data(
                                &mut data_fields,
                                &value_type_str,
                                &bytes,
                                &mut ctx.value_bytes,
                            );
                            let display_str = data_fields
                                .get("value_data")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string();
                            // The bytes themselves, for the decoders that
                            // need them -- and only from an anchored key.
                            if let Some(index) = resident_key {
                                ctx.resident.push_value(
                                    index,
                                    &value_name,
                                    value.data_type().ok(),
                                    &bytes,
                                );
                            }
                            (display_str, size)
                        }
                        Err(e) => {
                            warn!(
                                "Failed to convert value data for '{}' (type: {}) in key '{}': {}",
                                value_name, value_type_str, key_path, e
                            );
                            (format!("(error converting data: {})", e), 0)
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to read value '{}' (type: {}) in key '{}': {}",
                        value_name, value_type_str, key_path, e
                    );
                    (format!("(error reading value: {})", e), 0)
                }
            };

            if usb_instance.is_some()
                && value_name.eq_ignore_ascii_case("FriendlyName")
                && !value_data_str.is_empty()
            {
                usb_friendly_name = Some(value_data_str.clone());
            }

            let mut value_data = json!({
                "key_path": key_path,
                "value_name": value_name,
                "value_type": value_type_str,
                "value_data": value_data_str,
                "raw_data_size": raw_data_size,
            });
            if let Some(map) = value_data.as_object_mut() {
                data_fields.remove("value_data");
                map.extend(data_fields);
            }

            ctx.all_values.push(value_data);
        }
    }

    // Emit a USB device record once this instance key's values are read.
    if let Some((class, serial)) = usb_instance {
        let (vendor, product, revision) = parse_device_class(&class);
        ctx.usb_devices.push(json!({
            "device_class": class,
            "serial": serial,
            "vendor": vendor,
            "product": product,
            "revision": revision,
            "friendly_name": usb_friendly_name,
            "key_path": key_path,
        }));
    }

    // Recursively process subkeys. A refused subkey takes its whole subtree out
    // of the inventory, so the drop is counted and surfaced on the hive record.
    if let Some(subkeys_iter) = subkeys_iter {
        for subkey_node in subkeys_iter {
            let subkey_node = match subkey_node {
                Ok(n) => n,
                Err(_) => {
                    ctx.subkey_errors += 1;
                    continue;
                }
            };
            if let Ok(subkey_name) = subkey_node.name() {
                let subkey_path = format!("{}\\{}", key_path, subkey_name);

                // Recursive call
                traverse_registry_key(&subkey_node, &subkey_path, ctx, depth + 1);
            } else {
                ctx.subkey_errors += 1;
                warn!(
                    "Failed to get name for subkey in '{}' at depth {} (possible corruption or encoding issue)",
                    key_path, depth
                );
            }
        }
    }
}

/// Start of the hive bins data; all cell offsets stored on disk are relative to
/// this position.
const HBIN_BASE: usize = 0x1000;
/// Cap on NK cells collected from one hive. Large hives (SYSTEM/SOFTWARE) can
/// exceed 100k keys; bound the scan so a huge or hostile hive stays cheap.
const MAX_NK_CELLS: usize = 200_000;
/// Cap on emitted key-write timeline events per hive.
const MAX_REGISTRY_TIMELINE_EVENTS: usize = 50_000;

/// Outcome of the raw NK scan: the emitted key-write events plus whether either
/// cap stopped the scan short of the whole hive.
///
/// Forensic meaning: a capped scan reports fewer key-write moments than the hive
/// contains. Presented without this, an examiner reading a large SOFTWARE or
/// SYSTEM hive would conclude that no key was written after the last event
/// shown, when in truth the scan stopped early.
struct KeyWriteScan {
    events: Vec<Artifact>,
    /// Every allocated NK cell found, by bin-relative offset. Kept so the
    /// recovered-cell records can rebuild a deleted key's path through its
    /// live ancestors.
    live_cells: HashMap<u32, NkCell>,
    /// The NK cell cap stopped the walk: keys past it were never examined.
    cells_capped: bool,
    /// The event cap stopped emission: keys were parsed but not surfaced.
    events_capped: bool,
    /// The walk stopped on damage rather than on a cap: the hbin chain ended
    /// before the end of the hive on bytes that are not a bin header, a bin
    /// declared an impossible size, or a cell inside a bin declared a length
    /// that runs past the bin's end. The cells after that point were never
    /// examined, and a cap is not the reason.
    structure_stopped: bool,
}

impl KeyWriteScan {
    fn complete(&self) -> bool {
        !self.cells_capped && !self.events_capped && !self.structure_stopped
    }

    /// Why the scan is short of the whole hive, or `None` when it ran to
    /// completion. A cap can be raised; a broken bin chain cannot.
    fn cap_reason(&self) -> Option<&'static str> {
        match (self.cells_capped, self.events_capped) {
            (true, true) => Some("nk_cell_cap_and_timeline_event_cap"),
            (true, false) => Some("nk_cell_cap"),
            (false, true) => Some("timeline_event_cap"),
            (false, false) => {
                if self.structure_stopped {
                    Some("hbin_chain_ended_early")
                } else {
                    None
                }
            }
        }
    }
}

/// One parsed NK (key node) cell: its own name, parent cell offset (relative to
/// the hive bins data), and last-write FILETIME.
struct NkCell {
    name: String,
    parent_rel: u32,
    timestamp: u64,
    /// `KEY_HIVE_ENTRY` (0x0004): the hive's root. A real root's parent
    /// field is not `0xFFFFFFFF` — it holds whatever the kernel left there —
    /// so a parent chain ends on this flag, not on the sentinel alone.
    is_root: bool,
}

/// Scan a raw registry hive for NK (key node) cells and emit one `TimelineEvent`
/// per key carrying a valid last-write time.
///
/// This parses the on-disk cells directly rather than walking the key index,
/// which is what lets it reach a key the index no longer points at. It is
/// fully bounds-checked: every offset
/// and length is validated against the buffer before use, so malformed or
/// hostile hives cannot panic or allocate unbounded memory. Key paths are
/// rebuilt from the parent-pointer chain recorded in each NK cell.
fn extract_key_write_events(
    buffer: &[u8],
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
) -> KeyWriteScan {
    if buffer.len() < HBIN_BASE || &buffer[0..4] != b"regf" {
        // Not readable as a hive: either the buffer stops before the first bin
        // or it does not carry the `regf` signature. No cell was ever examined,
        // so this is `structure_stopped`, not a complete scan that happened to
        // find nothing — `complete()` must be false here or the hive artifact
        // would assert that no key was written after the last event shown, on
        // evidence that was never walked at all.
        return KeyWriteScan {
            events: Vec::new(),
            live_cells: HashMap::new(),
            cells_capped: false,
            events_capped: false,
            structure_stopped: true,
        };
    }

    // Pass 1: collect every allocated NK cell, keyed by its offset relative to
    // the hive bins data.
    let mut cells: HashMap<u32, NkCell> = HashMap::new();
    let mut hbin_pos = HBIN_BASE;
    let mut capped = false;
    // The bin chain stopped before the end of the hive on something that is not
    // a bin: the keys stored past that point were never examined, and that is a
    // different fact from a cap.
    let mut structure_stopped = false;

    // The base block declares how many bytes of bins the hive holds. A walk that
    // ends before that is a broken chain; a walk that ends after it has simply
    // reached the slack past the last bin, which is not a gap.
    let declared_bins = if buffer.len() >= 0x2C {
        read_u32(buffer, 0x28) as usize
    } else {
        0
    };

    while hbin_pos + 0x20 <= buffer.len() {
        if &buffer[hbin_pos..hbin_pos + 4] != b"hbin" {
            structure_stopped = declared_bins > 0 && (hbin_pos - HBIN_BASE) < declared_bins;
            break;
        }
        let hbin_size = read_u32(buffer, hbin_pos + 8) as usize;
        if hbin_size < 0x20 {
            structure_stopped = true;
            break;
        }
        let hbin_end = hbin_pos.saturating_add(hbin_size).min(buffer.len());

        // Walk the variable-length cells inside this hbin.
        let mut cell = hbin_pos + 0x20;
        while cell + 4 <= hbin_end {
            let raw_size = read_i32(buffer, cell);
            let cell_len = raw_size.unsigned_abs() as usize;
            if raw_size == 0 {
                // A zero cell size is the tail of a bin that was allocated and
                // never written. Nothing follows it to be missed, so this ends
                // the bin rather than breaking it.
                break;
            }
            if cell_len < 8 || cell + cell_len > hbin_end {
                // A cell shorter than its own header, or one running past the
                // end of its bin, is structural damage: every key stored after
                // it in this bin is unreachable and was never examined. Ending
                // the bin quietly would let the hive artifact report a complete
                // key-write timeline over evidence the walk did not read.
                structure_stopped = true;
                break;
            }
            // Negative cell size means the cell is allocated (in use).
            if raw_size < 0 {
                if let Some(nk) = parse_nk_cell(buffer, cell + 4, cell + cell_len) {
                    let rel = (cell - HBIN_BASE) as u32;
                    cells.insert(rel, nk);
                    if cells.len() >= MAX_NK_CELLS {
                        capped = true;
                        break;
                    }
                }
            }
            cell += cell_len;
        }

        if capped {
            warn!(
                "Registry NK scan hit cell cap ({}); remaining keys skipped",
                MAX_NK_CELLS
            );
            break;
        }
        hbin_pos = hbin_pos.saturating_add(hbin_size);
    }

    // Pass 2: emit a TimelineEvent per NK with a usable timestamp. In hive
    // offset order, so that when the event cap bites the subset it keeps is
    // the same on every run: a HashMap's iteration order is not, and a capped
    // scan that kept a different set of keys each time made `key_last_written`
    // on the records built from it unreproducible.
    let mut ordered: Vec<(&u32, &NkCell)> = cells.iter().collect();
    ordered.sort_by_key(|(offset, _)| **offset);
    let mut events = Vec::new();
    let mut events_capped = false;
    for (_, nk) in ordered {
        if events.len() >= MAX_REGISTRY_TIMELINE_EVENTS {
            warn!(
                "Registry timeline emission hit event cap ({}); remaining keys skipped",
                MAX_REGISTRY_TIMELINE_EVENTS
            );
            events_capped = true;
            break;
        }
        let timestamp = match filetime_to_rfc3339(nk.timestamp) {
            Some(t) => t,
            None => continue,
        };
        let path = build_key_path(nk, &cells);
        let event = Artifact::new(
            case_id,
            ArtifactType::TimelineEvent,
            None,
            json!({
                "timestamp": timestamp,
                "timestamp_desc": "Registry Key Last Written",
                "source_module": "plugin.windows.registry_parser",
                "short_desc": format!("Registry key written: {}", path),
                "key_path": path,
            }),
        )
        .with_parent(parent_id);
        events.push(event);
    }
    KeyWriteScan {
        events,
        live_cells: cells,
        cells_capped: capped,
        events_capped,
        structure_stopped,
    }
}

/// The most value bytes one hive record publishes as `value_data_b64`, summed
/// over its values larger than [`ALWAYS_PUBLISHED_VALUE_BYTES`] (`HUNT-159`).
///
/// The hive itself is capped at 512 MiB, and this is half that: a hive whose
/// large values pass it is pathological, and the values past it are counted
/// on the record rather than dropped silently.
pub(crate) const MAX_VALUE_BYTES_PER_HIVE: usize = 256 * 1024 * 1024;

/// A value this small always carries its bytes: its base64 is no longer than
/// the hex rendering the walk has always published for it.
const ALWAYS_PUBLISHED_VALUE_BYTES: usize = 64;

/// What one hive has spent of [`MAX_VALUE_BYTES_PER_HIVE`], and what it held
/// back.
pub(crate) struct ValueBytesBudget {
    limit: usize,
    spent: usize,
    pub(crate) omitted: u64,
}

impl ValueBytesBudget {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            limit,
            spent: 0,
            omitted: 0,
        }
    }

    /// Whether a value of `len` bytes gets its bytes published. A small value
    /// always does; a larger one while the hive's budget holds.
    pub(crate) fn admit(&mut self, len: usize) -> bool {
        if len <= ALWAYS_PUBLISHED_VALUE_BYTES {
            return true;
        }
        match self.spent.checked_add(len) {
            Some(total) if total <= self.limit => {
                self.spent = total;
                true
            }
            _ => {
                self.omitted += 1;
                false
            }
        }
    }

    /// State the cap and what it held back on the hive record, always — so
    /// "every value carries its bytes" and "nobody said" cannot read alike.
    pub(crate) fn stamp(&self, hive_metadata: &mut serde_json::Value) {
        let Some(map) = hive_metadata.as_object_mut() else {
            return;
        };
        map.insert("value_bytes_budget_bytes".into(), json!(self.limit));
        map.insert("value_bytes_complete".into(), json!(self.omitted == 0));
        map.insert("value_bytes_omitted".into(), json!(self.omitted));
        let detail = if self.omitted == 0 {
            format!(
                "every value the walk read carries its stored bytes in `value_data_b64`; values \
                 over {ALWAYS_PUBLISHED_VALUE_BYTES} bytes count against a per-hive cap of {} \
                 bytes, which this hive did not reach",
                self.limit
            )
        } else {
            format!(
                "{} values over {ALWAYS_PUBLISHED_VALUE_BYTES} bytes are published with their \
                 rendering and without `value_data_b64`, because the hive's values passed the \
                 per-hive cap of {} bytes; their bytes are in the hive, not on this record",
                self.omitted, self.limit
            )
        };
        map.insert("value_bytes_detail".into(), json!(detail));
    }
}

/// A `REG_MULTI_SZ` body's elements: UTF-16LE strings, each NUL-terminated,
/// with the empty strings (the list's own terminator, and any padding) left
/// out — the same elements the rendering joins with `" | "`.
pub(crate) fn multi_sz_elements(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    units
        .split(|&u| u == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// Render a value's bytes for display by its type name, the way the live
/// walk always has: strings as UTF-16LE, `DWORD`/`QWORD` as hex and decimal —
/// a `REG_DWORD_BIG_ENDIAN` as the big-endian number it is (`HUNT-158`) —
/// `MULTI_SZ` joined with `" | "`, and binary as hex up to 64 bytes, past
/// which the display collapses to a length. The stored bytes themselves travel
/// beside the rendering in `value_data_b64`, which the caller attaches
/// (`HUNT-159`). Shared with the recovered-cell records so a freed value reads
/// exactly like a live one would, and only its type says which it is.
///
/// The type names are matched exactly: `RegDWord` is a prefix of
/// `RegDWordBigEndian`, and a substring match decoded a big-endian value
/// little-endian.
pub(crate) fn display_value_data(value_type_str: &str, bytes: &[u8]) -> String {
    match value_type_str {
        "RegSZ" | "RegExpandSZ" => {
            if bytes.len() >= 2 {
                let u16_data: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                String::from_utf16_lossy(&u16_data)
            } else {
                "(empty string)".to_string()
            }
        }
        "RegDWord" | "RegDWordBigEndian" => match bytes.first_chunk::<4>() {
            Some(four) => {
                let val = if value_type_str == "RegDWordBigEndian" {
                    u32::from_be_bytes(*four)
                } else {
                    u32::from_le_bytes(*four)
                };
                format!("0x{:08x} ({})", val, val)
            }
            None => "(invalid DWORD)".to_string(),
        },
        "RegQWord" => match bytes.first_chunk::<8>() {
            Some(eight) => {
                let val = u64::from_le_bytes(*eight);
                format!("0x{:016x} ({})", val, val)
            }
            None => "(invalid QWORD)".to_string(),
        },
        "RegMultiSZ" => multi_sz_elements(bytes).join(" | "),
        _ if bytes.len() <= 64 => bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" "),
        _ => format!("{} bytes (binary data)", bytes.len()),
    }
}

/// Put a value's rendering, its stored bytes (budget permitting) and — for a
/// `REG_MULTI_SZ` — its elements onto its record. One door for the live walk
/// and the recovered cells, so the two publish the same fields.
pub(crate) fn publish_value_data(
    map: &mut serde_json::Map<String, serde_json::Value>,
    value_type_str: &str,
    bytes: &[u8],
    budget: &mut ValueBytesBudget,
) {
    map.insert(
        "value_data".into(),
        json!(display_value_data(value_type_str, bytes)),
    );
    if budget.admit(bytes.len()) {
        map.insert("value_data_b64".into(), json!(BASE64.encode(bytes)));
    } else {
        map.insert(
            "value_data_b64_omitted".into(),
            json!("the hive's per-hive cap on published value bytes was reached"),
        );
    }
    // The rendering joins the elements with a separator that is also a legal
    // character in an element; the array is exact.
    if value_type_str == "RegMultiSZ" {
        map.insert("value_data_list".into(), json!(multi_sz_elements(bytes)));
    }
}

/// Parse an NK cell body located at `data_start..cell_end`. Returns `None` if
/// the cell is not an NK record or is too short.
fn parse_nk_cell(buffer: &[u8], data_start: usize, cell_end: usize) -> Option<NkCell> {
    let hdr = buffer.get(data_start..cell_end)?;
    // 76-byte fixed header precedes the variable-length key name.
    if hdr.len() < 76 || &hdr[0..2] != b"nk" {
        return None;
    }
    let flags = u16::from_le_bytes([hdr[2], hdr[3]]);
    let timestamp = u64::from_le_bytes([
        hdr[4], hdr[5], hdr[6], hdr[7], hdr[8], hdr[9], hdr[10], hdr[11],
    ]);
    let parent_rel = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
    let name_len = u16::from_le_bytes([hdr[72], hdr[73]]) as usize;
    let name_end = 76usize.saturating_add(name_len).min(hdr.len());
    let name_bytes = hdr.get(76..name_end)?;
    // KEY_COMP_NAME (0x0020): the name is stored one byte per character in the
    // system ANSI code page; otherwise UTF-16LE.
    //
    // `b as char` is ISO-8859-1, which agrees with CP1252 from 0xA0 up and
    // disagrees below it: byte 0x92 became U+0092, an unprintable C1 control,
    // where the key was actually named with a right single quotation mark. Such
    // a key rendered as an unprintable and matched no keyword search, on a hive
    // where the key name is often the whole finding (REG-001).
    let name = if flags & 0x0020 != 0 {
        seance_core::codepage::decode(name_bytes, seance_core::codepage::CodePage::Cp1252).0
    } else {
        let units: Vec<u16> = name_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    };
    Some(NkCell {
        name,
        parent_rel,
        timestamp,
        is_root: flags & 0x0004 != 0,
    })
}

/// Rebuild the full key path for an NK by following parent pointers. A visited
/// set and depth bound defend against cyclic or corrupt parent chains.
fn build_key_path(start: &NkCell, cells: &HashMap<u32, NkCell>) -> String {
    const MAX_PATH_DEPTH: usize = 512;
    let mut parts: Vec<&str> = Vec::new();
    parts.push(if start.name.is_empty() {
        "(root)"
    } else {
        &start.name
    });

    let mut seen: HashSet<u32> = HashSet::new();
    let mut parent_rel = start.parent_rel;
    // The root ends the chain by its flag: a real root's parent field is not
    // the 0xFFFFFFFF sentinel, and following it prepends whatever key the
    // stray offset lands on to every path in the hive.
    if start.is_root {
        parent_rel = 0xFFFF_FFFF;
    }
    for _ in 0..MAX_PATH_DEPTH {
        // 0xFFFFFFFF terminates the root chain; a revisit means a cycle.
        if parent_rel == 0xFFFF_FFFF || !seen.insert(parent_rel) {
            break;
        }
        match cells.get(&parent_rel) {
            Some(parent) => {
                if !parent.name.is_empty() {
                    parts.push(&parent.name);
                }
                if parent.is_root {
                    break;
                }
                parent_rel = parent.parent_rel;
            }
            None => break,
        }
    }
    parts.reverse();
    parts.join("\\")
}

/// Read a little-endian u32, or 0 if the slice is too short.
fn read_u32(buf: &[u8], off: usize) -> u32 {
    buf.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

/// Read a little-endian i32, or 0 if the slice is too short.
fn read_i32(buf: &[u8], off: usize) -> i32 {
    buf.get(off..off + 4)
        .map(|s| i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

/// Windows FILETIME (100 ns since 1601-01-01) to an RFC3339 string. `None` for a
/// zero, pre-1970, or unrepresentable value (via the shared canonical helper, so
/// a corrupt cell can no longer produce a 1601-era timestamp).
fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    seance_core::time::filetime_to_rfc3339(filetime)
}

#[cfg(test)]
mod usb_tests {
    use super::{parse_device_class, parse_usbstor_instance};

    #[test]
    fn parses_usbstor_device_instance() {
        let deeper =
            "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C531001\\Properties";
        let instance =
            "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C531001530";
        let (class, serial) = parse_usbstor_instance(instance).unwrap();
        assert_eq!(class, "Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00");
        assert_eq!(serial, "4C531001530");
        // The USBSTOR root and class-only keys are not instances.
        assert!(parse_usbstor_instance("ControlSet001\\Enum\\USBSTOR").is_none());
        assert!(parse_usbstor_instance(
            "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00"
        )
        .is_none());
        // A deeper subkey under the instance is not itself an instance.
        assert!(parse_usbstor_instance(deeper).is_none());
    }

    /// HUNT-056. A stock Windows install ships a per-chipset quirk list under
    /// `Control\usbstor`, and SOFTWARE mirrors it under `Setup\PnpResources`.
    /// Neither records a device that was ever attached. Matching `\USBSTOR\`
    /// anywhere read them as five USB disks — serial number `DeviceHackFlags` —
    /// on a domain controller that has no `Enum\USBSTOR` key at all.
    ///
    /// Against the unfixed code every assertion below fails.
    #[test]
    fn the_drivers_compatibility_list_is_not_a_device_that_was_plugged_in() {
        // The exact paths off the DFIR Madness domain controller.
        assert!(parse_usbstor_instance(
            "ControlSet001\\Control\\usbstor\\054C00C1\\DeviceHackFlags"
        )
        .is_none());
        assert!(parse_usbstor_instance(
            "CsiTool-CreateHive-{0}\\Microsoft\\Windows\\CurrentVersion\\Setup\\PnpResources\\             Registry\\HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbstor\\05AC13xx\\DeviceHackFlags"
        )
        .is_none());
        // The driver database describes what a driver *can* bind to, not what
        // was attached.
        assert!(parse_usbstor_instance(
            "DriverDatabase\\DeviceIds\\USBSTOR\\DiskSony____MSC-U01N________\\Something"
        )
        .is_none());

        // The one shape that IS a device, still recognised, and case-insensitively.
        assert!(parse_usbstor_instance(
            "ControlSet001\\enum\\usbstor\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C531001530"
        )
        .is_some());
    }

    #[test]
    fn splits_vendor_product_revision() {
        let (ven, prod, rev) = parse_device_class("Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00");
        assert_eq!(ven.as_deref(), Some("SanDisk"));
        assert_eq!(prod.as_deref(), Some("Cruzer Blade"));
        assert_eq!(rev.as_deref(), Some("1.00"));
    }
}

#[cfg(test)]
mod typed_url_tests {
    use super::{build_typed_url_records, filetime_hex_to_unix};
    use serde_json::json;

    /// FILETIME for 2013-01-06T12:00:00Z, as the plugin's hex-byte display.
    fn filetime_hex(ft: u64) -> String {
        ft.to_le_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn filetime_decodes_to_unix() {
        // 130019472000000000 (100ns since 1601) == 2013-01-06T12:00:00Z.
        assert_eq!(
            filetime_hex_to_unix(&filetime_hex(130_019_472_000_000_000)),
            Some(1_357_473_600)
        );
        assert!(filetime_hex_to_unix("00 00 00 00 00 00 00 00").is_none());
        assert!(filetime_hex_to_unix("de ad").is_none()); // truncated
    }

    #[test]
    fn normalises_typed_urls_with_times() {
        let ie = "ROOT\\Software\\Microsoft\\Internet Explorer\\TypedURLs";
        let iet = "ROOT\\Software\\Microsoft\\Internet Explorer\\TypedURLsTime";
        let all_values = vec![
            json!({"key_path": ie, "value_name": "url1", "value_data": "https://example.com/"}),
            json!({"key_path": ie, "value_name": "url2", "value_data": "https://evidence.test/page"}),
            json!({"key_path": iet, "value_name": "url1", "value_data": filetime_hex(130_019_472_000_000_000)}),
            // Unrelated value under a different key must be ignored.
            json!({"key_path": "ROOT\\Software\\Foo", "value_name": "url9", "value_data": "nope"}),
        ];
        let parent = uuid::Uuid::new_v4();
        let replay = json!({ "recovered": true, "hive_dirty": true, "reason": "recovered" });
        let recs = build_typed_url_records(&all_values, uuid::Uuid::new_v4(), parent, &replay);
        assert_eq!(recs.len(), 2);

        let r1 = recs
            .iter()
            .find(|r| r.metadata["typed_order"] == 1)
            .unwrap();
        assert_eq!(r1.metadata["type"], "TypedUrl");
        assert_eq!(r1.metadata["url"], "https://example.com/");
        assert_eq!(r1.metadata["last_typed_time"].as_i64(), Some(1_357_473_600));
        assert_eq!(r1.parent_id, Some(parent));

        let r2 = recs
            .iter()
            .find(|r| r.metadata["typed_order"] == 2)
            .unwrap();
        assert_eq!(r2.metadata["url"], "https://evidence.test/page");
        assert!(r2.metadata.get("last_typed_time").is_none());

        // A URL read out of a recovered hive says so on the record itself: the
        // record travels far from its hive in lists, exports and reports.
        assert_eq!(r1.metadata["replay"]["recovered"], true);
        assert_eq!(r2.metadata["replay"]["hive_dirty"], true);
    }

    #[test]
    fn ignores_values_without_a_typedurls_key() {
        let all_values = vec![
            json!({"key_path": "ROOT\\Software\\Other", "value_name": "url1", "value_data": "x"}),
        ];
        let replay = json!({ "recovered": false, "hive_dirty": false, "reason": "clean" });
        assert!(build_typed_url_records(
            &all_values,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &replay
        )
        .is_empty());
    }
}
