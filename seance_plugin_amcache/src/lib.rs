#![forbid(unsafe_code)]
use chrono::{NaiveDateTime, TimeZone, Utc};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    file_detection::{detect_file_type, DetectedFileType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
// Shared with the other plugins that read a hive's primary file directly. It
// used to be a per-crate copy of the same module; a fix to one copy left the
// others telling an examiner a different completeness story about the same hive.
use seance_hive_util::{add_incomplete_reason, hive_state};
use serde_json::json;
use std::panic::{catch_unwind, AssertUnwindSafe};
use tracing::{debug, info, warn};

/// Upper bound on how much of an Amcache/RecentFileCache input is buffered into
/// RAM before parsing. A mis-detected or hostile large input must not OOM the
/// worker (BUG-132); the registry plugin caps the same way.
const MAX_AMCACHE_BYTES: u64 = 512 * 1024 * 1024;

/// Upper bound on entries emitted from one Amcache hive. `InventoryApplicationFile`
/// on a real workstation holds tens of thousands of subkeys; a hostile or damaged
/// hive can present far more. Hitting the cap is always stamped, never silent.
const MAX_AMCACHE_ENTRIES: usize = 250_000;

/// Upper bound on Win7 `RecentFileCache.bcf` records.
const MAX_BCF_ENTRIES: usize = 50_000;

/// What a walk over an Amcache container could not decode, and where it stopped.
///
/// Amcache answers "what was **present** on this machine". The keys this
/// reader takes — `InventoryApplicationFile` and `File` — are written when
/// Windows catalogues a file, and carry no run count and no last-run time; the
/// findings layer raises its own detections for them
/// (`inventoried_binary_*`) precisely so that presence is never reported as
/// execution. A subkey the hive parser refuses, or an entry beyond the cap, is
/// a file whose record never reaches the listing — and without a tally that is
/// indistinguishable from a file that was never there.
#[derive(Default, Clone, Copy)]
struct WalkTally {
    /// Subkey nodes (program entries, volume containers) the iterator errored on.
    subkey_errors: u64,
    /// Value nodes inside an entry that could not be read.
    value_errors: u64,
    /// Records that were structurally present but could not be decoded.
    record_errors: u64,
    /// The entry cap stopped the walk before the container ended.
    cap_reached: bool,
    /// Fewer bytes reached the parser than the source declared.
    short_read: bool,
    /// Entries emitted so far, used to enforce the cap. Not an incompleteness
    /// signal on its own.
    entries: usize,
}

impl WalkTally {
    /// True when everything the container holds reached the output.
    fn is_clean(&self) -> bool {
        self.subkey_errors == 0
            && self.value_errors == 0
            && self.record_errors == 0
            && !self.cap_reached
            && !self.short_read
    }

    /// Stable reason for the standard incompleteness pair. A cap and a corrupt
    /// record call for different follow-up, so they never share a reason.
    fn reason(&self) -> Option<&'static str> {
        if self.short_read {
            Some(IncompleteReason::ShortRead.as_str())
        } else if self.cap_reached {
            Some(IncompleteReason::CapReached.as_str())
        } else if !self.is_clean() {
            Some(IncompleteReason::UnresolvedStructure.as_str())
        } else {
            None
        }
    }
}

/// Stamp what a walk missed onto one artifact's metadata.
///
/// Always writes the counts, so "walk was clean" and "nobody counted" cannot
/// render identically; writes the standard incompleteness pair only when
/// something really was missed.
fn stamp_walk_tally(metadata: &mut serde_json::Value, tally: &WalkTally) {
    let Some(map) = metadata.as_object_mut() else {
        return;
    };
    map.insert("walk_subkey_errors".into(), json!(tally.subkey_errors));
    map.insert("walk_value_errors".into(), json!(tally.value_errors));
    map.insert("walk_record_errors".into(), json!(tally.record_errors));
    map.insert("walk_cap_reached".into(), json!(tally.cap_reached));
    if let Some(reason) = tally.reason() {
        add_incomplete_reason(map, reason);
        map.insert("inventory_incomplete".into(), json!(true));
        map.insert("inventory_incomplete_reason".into(), json!(reason));
    }
}

/// Convert an Amcache `LinkDate` value ("MM/DD/YYYY HH:MM:SS", the UTC PE link
/// timestamp of the file) to RFC 3339. Returns `None` for an empty or
/// unparseable value so the caller omits the timeline event rather than emit a
/// timestamp the DB batch insert would silently drop (BUG-100).
fn amcache_link_date_to_rfc3339(link_date: &str) -> Option<String> {
    let s = link_date.trim();
    if s.is_empty() {
        return None;
    }
    let naive = NaiveDateTime::parse_from_str(s, "%m/%d/%Y %H:%M:%S").ok()?;
    Some(Utc.from_utc_datetime(&naive).to_rfc3339())
}

/// Windows FILETIME ticks between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// A FILETIME as RFC 3339, or `None` for zero / out of range.
fn filetime_to_rfc3339(ft: u64) -> Option<String> {
    if ft < FILETIME_UNIX_EPOCH {
        return None;
    }
    let secs = (ft - FILETIME_UNIX_EPOCH) / 10_000_000;
    let dt = chrono::DateTime::<Utc>::from_timestamp(i64::try_from(secs).ok()?, 0)?;
    Some(dt.to_rfc3339())
}

/// Why a `LinkDate` is not put on the timeline as a point in time.
///
/// `LinkDate` is the PE header's link timestamp copied into the hive. A binary
/// cannot be linked after the registry key describing it was written, so a
/// value later than the key's own last-write time is not a time at all. On
/// Windows 10 and later Microsoft's binaries carry a reproducible-build hash in
/// that header field; on DFIR Madness Case 001 those rendered as `Amcache
/// LinkDate` events dated 2090, 2077 and 2049 and led the case timeline
/// (HUNT-076).
fn link_date_after_key_write(link_rfc3339: &str, key_written_filetime: u64) -> Option<String> {
    if key_written_filetime == 0 {
        return None;
    }
    let link = chrono::DateTime::parse_from_rfc3339(link_rfc3339).ok()?;
    let written = filetime_to_rfc3339(key_written_filetime)?;
    let written_dt = chrono::DateTime::parse_from_rfc3339(&written).ok()?;
    (link > written_dt).then(|| {
        format!(
            "LinkDate {link_rfc3339} is later than {written}, when the key recording this file \
             was last written; a PE link time cannot postdate the record of the file, so it is \
             kept on the record and not placed on the timeline. Windows 10 and later Microsoft \
             binaries carry a reproducible-build hash in this header field, not a time."
        )
    })
}

#[cfg(test)]
mod tests;

pub struct AmcacheParser;

impl ForensicsModule for AmcacheParser {
    fn id(&self) -> &str {
        "plugin.windows.amcache_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl AmcacheParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()),
        };

        // Name check: must relate to amcache. A prior version's `name` carries
        // the shadow-copy label, so the file's own name is read.
        let name = seance_core::shadow_copy::original_name(artifact).unwrap_or("");
        let lower_name = name.to_lowercase();

        // Win7 uses RecentFileCache.bcf (binary format, not a registry hive)
        if lower_name.contains("recentfilecache.bcf") {
            info!(
                "AmcacheParser: Detected Win7 RecentFileCache.bcf '{}' (artifact {})",
                name, artifact.id
            );
            let declared = data_source.size();
            let buffer = seance_core::io::read_capped(data_source.as_ref(), MAX_AMCACHE_BYTES);
            return Ok(parse_recent_file_cache(
                &buffer,
                declared,
                artifact.case_id,
                artifact.id,
                name,
            ));
        }

        // Win8+ uses Amcache.hve (registry hive)
        if !lower_name.contains("amcache") {
            return Ok(Vec::new());
        }

        // Content detection: must be a registry hive
        let detected_type = detect_file_type(data_source.as_ref());
        if detected_type != DetectedFileType::RegistryHive {
            return Ok(Vec::new());
        }

        info!(
            "AmcacheParser: Detected Amcache hive '{}' (artifact {})",
            name, artifact.id
        );

        // Read hive data (bounded: never allocate more than the cap).
        let buffer = seance_core::io::read_capped(data_source.as_ref(), MAX_AMCACHE_BYTES);

        // Amcache.hve is written continuously on a running system, so a copy
        // taken live is usually dirty: the newest execution/install entries sit
        // in `Amcache.hve.LOG1`/`.LOG2` and not in the primary file. This parser
        // does not replay them, so the absence of a program below cannot be
        // reported as evidence that it never ran.
        let recovery = hive_state::inspect(artifact, &buffer);
        if recovery.evidence_pending_in_logs() {
            warn!(
                "AmcacheParser: hive '{}' is dirty and its transaction logs ({}) were not \
                 replayed; recent execution evidence may be missing",
                name,
                recovery.logs_found.join(", ")
            );
        }
        if recovery.truncated() {
            warn!(
                "AmcacheParser: only {} of {} bytes of hive '{}' were loaded; \
                 entries beyond that point were never examined",
                recovery.bytes_read, recovery.declared_bytes, name
            );
        }

        // Parse with panic protection
        let case_id = artifact.case_id;
        let parent_id = artifact.id;

        let result = catch_unwind(AssertUnwindSafe(|| {
            parse_amcache_hive(&buffer, case_id, parent_id)
        }));

        match result {
            Ok(Ok((mut artifacts, tally))) => {
                info!(
                    "AmcacheParser: Produced {} artifacts from '{}'",
                    artifacts.len(),
                    name
                );
                if !tally.is_clean() {
                    warn!(
                        "AmcacheParser: hive '{}' walk incomplete: {} subkey errors, {} value \
                         errors, cap_reached={}",
                        name, tally.subkey_errors, tally.value_errors, tally.cap_reached
                    );
                }
                for a in &mut artifacts {
                    hive_state::stamp(&mut a.metadata, &recovery);
                    stamp_walk_tally(&mut a.metadata, &tally);
                }
                // Nothing recovered from a hive we know is dirty, short, capped
                // or partly undecodable reads exactly like a machine on which
                // nothing ever ran.
                if artifacts.is_empty() && (recovery.incomplete() || !tally.is_clean()) {
                    let mut status =
                        hive_state::status_artifact(case_id, parent_id, name, &recovery);
                    stamp_walk_tally(&mut status.metadata, &tally);
                    artifacts.push(status);
                }
                Ok(artifacts)
            }
            Ok(Err(e)) => {
                debug!("AmcacheParser: Failed to parse '{}': {}", name, e);
                // A file that reached here is a registry hive named amcache. It
                // failing to parse is a fact about the evidence, not an absence
                // of execution records.
                Ok(vec![parse_failure_status_artifact(
                    case_id, parent_id, name, &recovery, &e,
                )])
            }
            Err(panic_info) => {
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                warn!("AmcacheParser: Caught panic processing '{}': {}", name, msg);
                Ok(vec![parse_failure_status_artifact(
                    case_id,
                    parent_id,
                    name,
                    &recovery,
                    &format!("hive parser panicked: {}", msg),
                )])
            }
        }
    }
}

/// Record that the hive was recognised but yielded nothing because the parse
/// itself failed or aborted.
///
/// Without this, a panic or hard parse error on a dirty Amcache returns exactly
/// what a clean hive from a machine on which nothing ran returns: nothing.
fn parse_failure_status_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    hive_name: &str,
    state: &hive_state::HiveRecoveryState,
    detail: &str,
) -> Artifact {
    let mut metadata = json!({
        "type": "RegistryHiveParseStatus",
        "record_type": "registry_hive_parse_status",
        "name": format!("{} (parse failed)", hive_name),
        "hive_name": hive_name,
        "parse_failed": true,
        "parse_failure_detail": detail,
        "message": "This Amcache hive was recognised but could not be parsed; no execution \
                    records were read from it. The absence of entries below is not evidence \
                    that no program ran.",
    });
    hive_state::stamp(&mut metadata, state);
    if let Some(map) = metadata.as_object_mut() {
        add_incomplete_reason(map, IncompleteReason::UnresolvedStructure.as_str());
        map.insert("inventory_incomplete".into(), json!(true));
        map.insert(
            "inventory_incomplete_reason".into(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
    }
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}

/// Parse Windows 7 RecentFileCache.bcf binary format.
///
/// Format: a header whose first four bytes are a signature — `0xDEADBEEF` is
/// the one this reader recognises, and anything else falls through to a
/// four-byte header read — then variable-length records:
///   - 4 bytes: Unicode string length (in bytes, including null terminator)
///   - N bytes: UTF-16LE file path (null-terminated)
fn parse_recent_file_cache(
    buffer: &[u8],
    declared_bytes: u64,
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    name: &str,
) -> Vec<Artifact> {
    let mut artifacts = Vec::new();
    let mut tally = WalkTally {
        short_read: (buffer.len() as u64) < declared_bytes,
        ..WalkTally::default()
    };

    if buffer.len() < 20 {
        debug!("RecentFileCache.bcf too small: {} bytes", buffer.len());
        // A file the module already recognised by name, too short to hold a
        // header, is a truncated cache — not a machine with no recent files.
        tally.record_errors += 1;
        return vec![bcf_status_artifact(
            case_id,
            parent_id,
            name,
            &tally,
            buffer.len() as u64,
            declared_bytes,
        )];
    }

    // The file begins with a header whose first four bytes are a signature.
    // `0xDEADBEEF` is the only one this reader recognises, and it implies a
    // 20-byte header; anything else falls through to reading four. An earlier
    // comment here claimed a version byte `0x03` was also known, which the
    // code has never tested for.
    let header_sig = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

    let header_size = if header_sig == 0xDEADBEEF {
        // Standard header: 20 bytes
        20usize
    } else {
        // Try 4-byte header as fallback
        debug!(
            "RecentFileCache.bcf: non-standard header signature 0x{:08X}, trying 4-byte header",
            header_sig
        );
        4
    };

    let mut offset = header_size;
    let max_entries = MAX_BCF_ENTRIES; // safety limit

    while offset + 4 <= buffer.len() && artifacts.len() < max_entries {
        // Read string length (4 bytes, LE)
        let str_len = u32::from_le_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]) as usize;

        offset += 4;

        // Sanity checks. A record that fails them ends the walk: the stream is
        // sequential, so everything after it is unreachable. That is a fact
        // about the file, and it is counted rather than dropped.
        if str_len == 0 || str_len > 2048 || offset + str_len > buffer.len() {
            tally.record_errors += 1;
            break;
        }

        // Decode UTF-16LE string
        let str_data = &buffer[offset..offset + str_len];
        let u16_chars: Vec<u16> = str_data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let file_path = String::from_utf16_lossy(&u16_chars);

        offset += str_len;

        if file_path.is_empty() {
            continue;
        }

        let filename = file_path.rsplit('\\').next().unwrap_or(&file_path);
        let short_desc = format!("Amcache (Win7): {}", filename);

        let parsed = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "AmcacheEntry",
                "file_path": file_path,
                "format": "win7_recentfilecache",
                "short_desc": short_desc,
            }),
        )
        .with_parent(parent_id);

        artifacts.push(parsed);
    }

    // The cap stopped us with bytes still unread: the remainder is unexamined.
    if artifacts.len() >= max_entries && offset + 4 <= buffer.len() {
        tally.cap_reached = true;
    }

    info!("RecentFileCache.bcf: parsed {} entries", artifacts.len());

    if !tally.is_clean() {
        warn!(
            "RecentFileCache.bcf '{}': incomplete walk ({} of {} bytes read, {} bad records, \
             cap_reached={})",
            name,
            buffer.len(),
            declared_bytes,
            tally.record_errors,
            tally.cap_reached
        );
        for a in &mut artifacts {
            stamp_walk_tally(&mut a.metadata, &tally);
        }
        if artifacts.is_empty() {
            artifacts.push(bcf_status_artifact(
                case_id,
                parent_id,
                name,
                &tally,
                buffer.len() as u64,
                declared_bytes,
            ));
        }
    }

    artifacts
}

/// Record that a Win7 `RecentFileCache.bcf` was recognised but not read whole.
///
/// An empty return from a truncated cache reads as "this user opened no files";
/// this artifact is what makes the two outcomes distinguishable.
fn bcf_status_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    name: &str,
    tally: &WalkTally,
    bytes_read: u64,
    declared_bytes: u64,
) -> Artifact {
    let mut metadata = json!({
        "type": "AmcacheParseStatus",
        "record_type": "amcache_parse_status",
        "name": format!("{} (incomplete)", name),
        "format": "win7_recentfilecache",
        "bytes_read": bytes_read,
        "declared_bytes": declared_bytes,
        "message": "This RecentFileCache was recognised but was not read to its end; the \
                    absence of a file below is not evidence that it was never opened.",
    });
    stamp_walk_tally(&mut metadata, tally);
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}

fn parse_amcache_hive(
    buffer: &[u8],
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
) -> Result<(Vec<Artifact>, WalkTally), String> {
    let hive = seance_hive_util::open_hive(buffer)?;
    let root = hive
        .root_key_node()
        .map_err(|e| format!("Failed to get root key: {}", e))?;

    let mut artifacts = Vec::new();
    let mut tally = WalkTally::default();

    // Navigate to the "Root" subkey first (Amcache hive structure: CMI-CreateHive{...}\Root\...)
    // Then look for InventoryApplicationFile (Win10+) or File (Win8)
    let search_key = match root.subkeys() {
        Some(Ok(subkeys)) => {
            let mut root_subkey = None;
            tally.subkey_errors += subkeys.unresolved_sublists().len() as u64;
            for subkey in subkeys {
                let subkey = match subkey {
                    Ok(k) => k,
                    Err(_) => {
                        tally.subkey_errors += 1;
                        continue;
                    }
                };
                let key_name = subkey.name().map(|n| n.to_string()).unwrap_or_default();
                if key_name == "Root" {
                    root_subkey = Some(subkey);
                    break;
                }
                // Also check immediate children in case the root IS the container
                if key_name == "InventoryApplicationFile" || key_name == "File" {
                    root_subkey = None;
                    break;
                }
            }
            root_subkey
        }
        Some(Err(_)) => {
            tally.subkey_errors += 1;
            None
        }
        None => None,
    };

    // If we found a "Root" subkey, search within it; otherwise search from hive root
    let search_from = if search_key.is_some() {
        // Re-navigate to get fresh iterators
        match root.subkeys() {
            Some(Ok(subkeys)) => {
                // The root's own unresolved `ri` sublists are counted once, at
                // the first navigation above (HIVE-002); this is the same key
                // re-walked for a fresh iterator, so counting again would
                // inflate the hive's completeness figure.
                for subkey in subkeys {
                    let subkey = match subkey {
                        Ok(k) => k,
                        Err(_) => {
                            tally.subkey_errors += 1;
                            continue;
                        }
                    };
                    let key_name = subkey.name().map(|n| n.to_string()).unwrap_or_default();
                    if key_name == "Root" {
                        match subkey.subkeys() {
                            Some(Ok(root_children)) => {
                                // An `ri` sublist that would not read is a hole in the walk, not a
                                // shorter key (HIVE-002).
                                tally.subkey_errors +=
                                    root_children.unresolved_sublists().len() as u64;
                                for child in root_children {
                                    let child = match child {
                                        Ok(c) => c,
                                        Err(_) => {
                                            tally.subkey_errors += 1;
                                            continue;
                                        }
                                    };
                                    let child_name =
                                        child.name().map(|n| n.to_string()).unwrap_or_default();
                                    if child_name == "InventoryApplicationFile" {
                                        parse_inventory_application_file(
                                            &child,
                                            case_id,
                                            parent_id,
                                            &mut artifacts,
                                            &mut tally,
                                        );
                                    } else if child_name == "File" {
                                        parse_legacy_file_entries(
                                            &child,
                                            case_id,
                                            parent_id,
                                            &mut artifacts,
                                            &mut tally,
                                        );
                                    }
                                }
                            }
                            Some(Err(_)) => tally.subkey_errors += 1,
                            None => {}
                        }
                        break;
                    }
                }
            }
            Some(Err(_)) => tally.subkey_errors += 1,
            None => {}
        }
        true
    } else {
        false
    };

    // Also try directly from root in case there's no "Root" subkey
    if !search_from || artifacts.is_empty() {
        match root.subkeys() {
            Some(Ok(subkeys)) => {
                // The root's own unresolved `ri` sublists are counted once, at
                // the first navigation above (HIVE-002); this is the same key
                // re-walked for a fresh iterator, so counting again would
                // inflate the hive's completeness figure.
                for subkey in subkeys {
                    let subkey = match subkey {
                        Ok(k) => k,
                        Err(_) => {
                            tally.subkey_errors += 1;
                            continue;
                        }
                    };
                    let key_name = subkey.name().map(|n| n.to_string()).unwrap_or_default();
                    if key_name == "InventoryApplicationFile" {
                        parse_inventory_application_file(
                            &subkey,
                            case_id,
                            parent_id,
                            &mut artifacts,
                            &mut tally,
                        );
                    } else if key_name == "File" {
                        parse_legacy_file_entries(
                            &subkey,
                            case_id,
                            parent_id,
                            &mut artifacts,
                            &mut tally,
                        );
                    }
                }
            }
            Some(Err(_)) => tally.subkey_errors += 1,
            None => {}
        }
    }

    Ok((artifacts, tally))
}

/// Parse Win10+ InventoryApplicationFile entries
fn parse_inventory_application_file(
    key: &seance_hive::KeyNode<'_>,
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    artifacts: &mut Vec<Artifact>,
    tally: &mut WalkTally,
) {
    let subkeys = match key.subkeys() {
        Some(Ok(sk)) => {
            tally.subkey_errors += sk.unresolved_sublists().len() as u64;
            sk
        }
        Some(Err(_)) => {
            tally.subkey_errors += 1;
            return;
        }
        None => return,
    };

    for entry in subkeys {
        if tally.entries >= MAX_AMCACHE_ENTRIES {
            tally.cap_reached = true;
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                tally.subkey_errors += 1;
                continue;
            }
        };
        let entry_name = entry.name().map(|n| n.to_string()).unwrap_or_default();
        let key_written = entry.last_written_filetime();

        let mut file_path = String::new();
        let mut sha1_hash = String::new();
        let mut file_size: Option<u64> = None;
        let mut link_date = String::new();
        let mut program_id = String::new();
        let mut publisher = String::new();
        let mut version = String::new();

        match entry.values() {
            Some(Ok(values)) => {
                for value in values {
                    let value = match value {
                        Ok(v) => v,
                        Err(_) => {
                            tally.value_errors += 1;
                            continue;
                        }
                    };
                    let val_name = value.name().map(|n| n.to_string()).unwrap_or_default();
                    let val_data = match value.data().ok().and_then(|d| d.into_vec().ok()) {
                        Some(d) => d,
                        None => {
                            tally.value_errors += 1;
                            continue;
                        }
                    };

                    match val_name.as_str() {
                        "LowerCaseLongPath" | "15" => {
                            file_path = decode_reg_sz(&val_data);
                        }
                        "FileId" | "101" => {
                            sha1_hash = decode_reg_sz(&val_data);
                            // Amcache prefixes SHA1 with "0000"
                            if sha1_hash.starts_with("0000") {
                                sha1_hash = sha1_hash[4..].to_string();
                            }
                        }
                        "Size" | "6" => {
                            // A Size field too short to decode is unknown, not
                            // zero: a fabricated 0-byte size is a forensic claim.
                            file_size = decode_amcache_size(&val_data);
                            if file_size.is_none() {
                                tally.value_errors += 1;
                            }
                        }
                        "LinkDate" | "f" => {
                            link_date = decode_reg_sz(&val_data);
                        }
                        "ProgramId" | "7" => {
                            program_id = decode_reg_sz(&val_data);
                        }
                        "Publisher" | "1" => {
                            publisher = decode_reg_sz(&val_data);
                        }
                        "Version" | "5" => {
                            version = decode_reg_sz(&val_data);
                        }
                        _ => {}
                    }
                }
            }
            Some(Err(_)) => tally.value_errors += 1,
            None => {}
        }

        if file_path.is_empty() && sha1_hash.is_empty() {
            continue;
        }

        let short_desc = if !file_path.is_empty() {
            let filename = file_path.rsplit('\\').next().unwrap_or(&file_path);
            format!("Amcache: {}", filename)
        } else {
            format!("Amcache entry: {}", entry_name)
        };

        // BUG-100: LinkDate is "MM/DD/YYYY HH:MM:SS"; the DB timeline insert only
        // accepts unix seconds or RFC 3339 and silently drops anything else. Emit
        // the timeline event only with a converted RFC 3339 timestamp. The raw
        // string is still preserved on the ParsedRecord.
        let link_rfc3339 = amcache_link_date_to_rfc3339(&link_date);
        // HUNT-076: a LinkDate later than the key's own last write is not a
        // time; it stays on the record, with the reason, and off the timeline.
        let link_date_note = link_rfc3339
            .as_deref()
            .and_then(|ts| link_date_after_key_write(ts, key_written));

        let mut record = json!({
            "type": "AmcacheEntry",
            "file_path": file_path,
            "sha1_hash": sha1_hash,
            "file_size": file_size,
            "link_date": link_date,
            "key_last_written": filetime_to_rfc3339(key_written),
            "program_id": program_id,
            "publisher": publisher,
            "version": version,
            "entry_name": entry_name,
            "short_desc": short_desc,
        });
        if let Some(note) = &link_date_note {
            record["link_date_plausible"] = json!(false);
            record["link_date_note"] = json!(note);
        } else if link_rfc3339.is_some() {
            record["link_date_plausible"] = json!(true);
        }
        let parsed =
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, record).with_parent(parent_id);

        match link_rfc3339.filter(|_| link_date_note.is_none()) {
            Some(ts) => {
                let timeline = Artifact::new(
                    case_id,
                    ArtifactType::TimelineEvent,
                    None,
                    json!({
                        "timestamp_desc": "Amcache LinkDate (PE link time)",
                        "timestamp": ts,
                        "source_module": "plugin.windows.amcache_parser",
                        "short_desc": short_desc,
                        "full_details": json!({
                            "file_path": file_path,
                            "sha1": sha1_hash,
                            "publisher": publisher,
                            "link_date_raw": link_date,
                        }).to_string(),
                    }),
                )
                .with_parent(parsed.id);

                artifacts.push(parsed);
                artifacts.push(timeline);
            }
            None => artifacts.push(parsed),
        }
        tally.entries += 1;
    }
}

/// Parse legacy Win8 File entries (Root\File\{volume_guid}\{entry_id})
fn parse_legacy_file_entries(
    key: &seance_hive::KeyNode<'_>,
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    artifacts: &mut Vec<Artifact>,
    tally: &mut WalkTally,
) {
    let volume_subkeys = match key.subkeys() {
        Some(Ok(sk)) => {
            tally.subkey_errors += sk.unresolved_sublists().len() as u64;
            sk
        }
        Some(Err(_)) => {
            tally.subkey_errors += 1;
            return;
        }
        None => return,
    };

    for volume_key in volume_subkeys {
        let volume_key = match volume_key {
            Ok(k) => k,
            Err(_) => {
                tally.subkey_errors += 1;
                continue;
            }
        };
        let entries = match volume_key.subkeys() {
            Some(Ok(sk)) => {
                tally.subkey_errors += sk.unresolved_sublists().len() as u64;
                sk
            }
            Some(Err(_)) => {
                tally.subkey_errors += 1;
                continue;
            }
            None => continue,
        };

        for entry in entries {
            if tally.entries >= MAX_AMCACHE_ENTRIES {
                tally.cap_reached = true;
                return;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    tally.subkey_errors += 1;
                    continue;
                }
            };
            let mut file_path = String::new();
            let mut sha1_hash = String::new();

            match entry.values() {
                Some(Ok(values)) => {
                    for value in values {
                        let value = match value {
                            Ok(v) => v,
                            Err(_) => {
                                tally.value_errors += 1;
                                continue;
                            }
                        };
                        let val_name = value.name().map(|n| n.to_string()).unwrap_or_default();
                        let val_data = match value.data().ok().and_then(|d| d.into_vec().ok()) {
                            Some(d) => d,
                            None => {
                                tally.value_errors += 1;
                                continue;
                            }
                        };

                        match val_name.as_str() {
                            "15" => file_path = decode_reg_sz(&val_data),
                            "101" => {
                                sha1_hash = decode_reg_sz(&val_data);
                                if sha1_hash.starts_with("0000") {
                                    sha1_hash = sha1_hash[4..].to_string();
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Some(Err(_)) => tally.value_errors += 1,
                None => {}
            }

            if file_path.is_empty() {
                continue;
            }

            let short_desc = format!(
                "Amcache (legacy): {}",
                file_path.rsplit('\\').next().unwrap_or(&file_path)
            );

            let parsed = Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "AmcacheEntry",
                    "file_path": file_path,
                    "sha1_hash": sha1_hash,
                    "format": "legacy_win8",
                    "short_desc": short_desc,
                }),
            )
            .with_parent(parent_id);

            artifacts.push(parsed);
            tally.entries += 1;
        }
    }
}

/// Decode an Amcache `Size` value. Real InventoryApplicationFile hives store it
/// as REG_QWORD (8 bytes LE); some older/rare entries use a 4-byte DWORD. Reading
/// only 4 bytes truncated any size >= 4 GiB (BUG-106).
///
/// Returns `None` for data too short to hold either encoding: an undecodable
/// size is unknown, and reporting it as 0 bytes states something about the file
/// that the evidence does not say.
fn decode_amcache_size(data: &[u8]) -> Option<u64> {
    if data.len() >= 8 {
        Some(u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]))
    } else if data.len() >= 4 {
        Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64)
    } else {
        None
    }
}

/// Decode REG_SZ (UTF-16LE) data to a Rust String
fn decode_reg_sz(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let u16_data: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&u16_data)
}
