#![forbid(unsafe_code)]
pub mod format;

// Shared with the other plugins that read a hive's primary file directly. It
// used to be a per-crate copy of the same module; a fix to one copy left the
// others telling an examiner a different completeness story about the same hive.
use seance_hive_util::{add_incomplete_reason, hive_state};

use format::{
    detect_version, parse_vista_entries, parse_win10_entries, parse_win7_entries,
    parse_win81_entries, AppCompatCacheVersion,
};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    file_detection::{try_detect_file_type, DetectedFileType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::panic::{catch_unwind, AssertUnwindSafe};
use tracing::{debug, info, warn};

/// Upper bound on how much of a hive is buffered into RAM before parsing. A
/// mis-detected or hostile large input must not OOM the worker (BUG-132); the
/// registry plugin caps the same way.
const MAX_HIVE_BYTES: u64 = 512 * 1024 * 1024;

pub struct ShimcacheParser;

impl ForensicsModule for ShimcacheParser {
    fn id(&self) -> &str {
        "plugin.windows.shimcache_parser"
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

impl ShimcacheParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()),
        };

        // Content detection: must be a registry hive
        // An unreadable header is "could not look", not "not a hive" (CR-047).
        if try_detect_file_type(data_source.as_ref()).map_err(ModuleError::IoError)?
            != DetectedFileType::RegistryHive
        {
            return Ok(Vec::new());
        }

        // Name check: must contain "system" (case-insensitive)
        let name = seance_core::shadow_copy::original_name(artifact).unwrap_or("");
        if !name.to_lowercase().contains("system") {
            return Ok(Vec::new());
        }

        info!(
            "ShimcacheParser: Detected SYSTEM hive '{}' (artifact {})",
            name, artifact.id
        );

        // Read hive data (bounded: never allocate more than the cap).
        let buffer = seance_core::io::read_capped(data_source.as_ref(), MAX_HIVE_BYTES);

        // A SYSTEM hive copied from a running machine keeps its newest writes in
        // `SYSTEM.LOG1`/`.LOG2`. AppCompatCache is only flushed to the primary
        // file at shutdown, so on a dirty hive the cache read below can predate
        // the last executions entirely. Say so rather than presenting it as the
        // machine's execution history.
        let recovery = hive_state::inspect(artifact, &buffer);
        if recovery.evidence_pending_in_logs() {
            warn!(
                "ShimcacheParser: hive '{}' is dirty and its transaction logs ({}) were not \
                 replayed; AppCompatCache may predate the most recent executions",
                name,
                recovery.logs_found.join(", ")
            );
        }
        if recovery.truncated() {
            warn!(
                "ShimcacheParser: only {} of {} bytes of hive '{}' were loaded; \
                 the AppCompatCache value may not have been reached",
                recovery.bytes_read, recovery.declared_bytes, name
            );
        }

        let case_id = artifact.case_id;
        let parent_id = artifact.id;

        let result = catch_unwind(AssertUnwindSafe(|| {
            parse_shimcache_from_hive(&buffer, case_id, parent_id)
        }));

        match result {
            Ok(Ok(mut artifacts)) => {
                info!(
                    "ShimcacheParser: Produced {} artifacts from '{}'",
                    artifacts.len(),
                    name
                );
                for a in &mut artifacts {
                    hive_state::stamp(&mut a.metadata, &recovery);
                }
                Ok(artifacts)
            }
            Ok(Err(ParseFailure::CacheNotFound)) => {
                debug!(
                    "ShimcacheParser: no AppCompatCache value in any ControlSet of '{}'",
                    name
                );
                // No AppCompatCache found in a hive that is dirty or was not
                // read in full: an empty result here would otherwise be
                // indistinguishable from a machine that executed nothing.
                if recovery.incomplete() {
                    return Ok(vec![hive_state::status_artifact(
                        case_id, parent_id, name, &recovery,
                    )]);
                }
                Ok(Vec::new())
            }
            Ok(Err(ParseFailure::HiveUnreadable(e))) => {
                debug!("ShimcacheParser: Failed to parse '{}': {}", name, e);
                // The file is a registry hive named SYSTEM that could not be
                // read. Returning nothing would read as "nothing ever ran".
                Ok(vec![hive_failure_artifact(
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
                warn!(
                    "ShimcacheParser: Caught panic processing '{}': {}",
                    name, msg
                );
                Ok(vec![hive_failure_artifact(
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

/// Why a hive produced no Shimcache records.
///
/// The two outcomes need different reporting: a SYSTEM hive that simply carries
/// no AppCompatCache value is ordinary, while a hive that could not be read at
/// all leaves the machine's execution history unknown.
enum ParseFailure {
    /// The hive parsed; no AppCompatCache value exists in any ControlSet.
    CacheNotFound,
    /// The hive itself could not be opened or walked.
    HiveUnreadable(String),
}

/// Record that a SYSTEM hive was recognised but could not be read, so its
/// AppCompatCache was never reached.
fn hive_failure_artifact(
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
        "message": "This SYSTEM hive could not be parsed, so its AppCompatCache was never \
                    read. The absence of execution entries is not evidence that nothing ran.",
    });
    hive_state::stamp(&mut metadata, state);
    if let Some(map) = metadata.as_object_mut() {
        add_incomplete_reason(
            map,
            seance_core::io::IncompleteReason::UnresolvedStructure.as_str(),
        );
        map.insert("inventory_incomplete".into(), json!(true));
        map.insert(
            "inventory_incomplete_reason".into(),
            json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
        );
    }
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}

/// Stamp what one AppCompatCache walk missed onto an artifact.
fn stamp_cache_walk(metadata: &mut serde_json::Value, parse: &format::CacheParse) {
    let Some(map) = metadata.as_object_mut() else {
        return;
    };
    map.insert("walk_cap_reached".into(), json!(parse.cap_reached));
    map.insert("walk_stopped_early".into(), json!(parse.stopped_early));
    map.insert(
        "walk_undecodable_records".into(),
        json!(parse.undecodable_records),
    );
    if let Some(declared) = parse.declared_entries {
        map.insert("declared_entries".into(), json!(declared));
    }
    if let Some(reason) = parse.incomplete_reason() {
        add_incomplete_reason(map, reason);
        map.insert("inventory_incomplete".into(), json!(true));
        map.insert("inventory_incomplete_reason".into(), json!(reason));
    }
}

fn parse_shimcache_from_hive(
    buffer: &[u8],
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
) -> Result<Vec<Artifact>, ParseFailure> {
    let hive = seance_hive_util::open_hive(buffer).map_err(ParseFailure::HiveUnreadable)?;
    let root = hive
        .root_key_node()
        .map_err(|e| ParseFailure::HiveUnreadable(format!("Failed to get root key: {}", e)))?;

    // Every ControlSet is parsed, not just the first one that yields entries.
    // A SYSTEM hive keeps the previous boot's control set alongside the current
    // one, and its AppCompatCache can name programs that have since been purged
    // from the live set. Stopping at the first hit silently discards that
    // history while still reporting a successful parse.
    let control_set_names = ["ControlSet001", "ControlSet002", "CurrentControlSet"];
    let mut all_artifacts: Vec<Artifact> = Vec::new();
    // CurrentControlSet is an alias for one of the numbered sets, so the same
    // cache can be reached twice. Compare the raw value bytes to emit it once.
    let mut seen_caches: Vec<Vec<u8>> = Vec::new();
    // Key/value nodes the hive parser refused while navigating. One of them can
    // be the ControlSet that holds the cache.
    let mut key_errors: u64 = 0;

    for cs_name in &control_set_names {
        if let Some(appcompat_data) = navigate_to_appcompat_cache(&root, cs_name, &mut key_errors) {
            if seen_caches.iter().any(|c| c == &appcompat_data) {
                continue;
            }
            let version = match detect_version(&appcompat_data) {
                Some(v) => v,
                None => {
                    // The value is there; its layout matches no known
                    // AppCompatCache version. Walking it anyway would invent
                    // execution records, and skipping it silently would present
                    // the machine as having none.
                    warn!(
                        "ShimcacheParser: AppCompatCache in {} has an unrecognised format \
                         ({} bytes); no entries parsed",
                        cs_name,
                        appcompat_data.len()
                    );
                    all_artifacts.push(cache_status_artifact(
                        case_id,
                        parent_id,
                        cs_name,
                        appcompat_data.len(),
                        None,
                        0,
                        Some("format_unrecognised"),
                    ));
                    seen_caches.push(appcompat_data);
                    continue;
                }
            };

            info!(
                "ShimcacheParser: Found AppCompatCache in {} (format: {:?}, {} bytes)",
                cs_name,
                version,
                appcompat_data.len()
            );

            let parse = match version {
                AppCompatCacheVersion::Win10 => parse_win10_entries(&appcompat_data),
                AppCompatCacheVersion::Win81 => parse_win81_entries(&appcompat_data),
                AppCompatCacheVersion::Win7 => parse_win7_entries(&appcompat_data),
                AppCompatCacheVersion::Vista => parse_vista_entries(&appcompat_data),
            };
            let entries = &parse.entries;
            let cache_len = appcompat_data.len();

            seen_caches.push(appcompat_data);

            if entries.is_empty() {
                // A cache value that yielded no entries is reported, so that
                // "the cache held nothing" and "the cache could not be walked"
                // are distinguishable.
                let mut status = cache_status_artifact(
                    case_id,
                    parent_id,
                    cs_name,
                    cache_len,
                    Some(version),
                    0,
                    None,
                );
                stamp_cache_walk(&mut status.metadata, &parse);
                all_artifacts.push(status);
                continue;
            }

            let mut artifacts = Vec::with_capacity(entries.len() * 2);
            for (i, entry) in entries.iter().enumerate() {
                let filename = entry.path.rsplit('\\').next().unwrap_or(&entry.path);
                let short_desc = format!("Shimcache #{}: {}", i + 1, filename);

                let timestamp_str = entry
                    .last_modified
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default();

                let parsed = Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "ShimcacheEntry",
                        "path": entry.path,
                        "last_modified": timestamp_str,
                        // Three states on the wire: `true`, `false`, and
                        // `null`. Null means this cache format records no
                        // execution flag, so nothing is known either way — a
                        // consumer that renders null as "not executed" states
                        // a negative finding nobody measured (B8-010).
                        "exec_flag": entry.exec_flag,
                        "data_size": entry.data_size,
                        "position": i + 1,
                        "control_set": cs_name,
                        "format_version": format!("{:?}", version),
                        "short_desc": short_desc,
                    }),
                )
                .with_parent(parent_id);

                if entry.last_modified.is_some() {
                    let timeline = Artifact::new(
                        case_id,
                        ArtifactType::TimelineEvent,
                        None,
                        json!({
                            "timestamp": timestamp_str,
                            "timestamp_desc": "Shimcache LastModified",
                            "source_module": "plugin.windows.shimcache_parser",
                            "short_desc": short_desc,
                            "full_details": json!({
                                "path": entry.path,
                                "exec_flag": entry.exec_flag,
                                "position": i + 1,
                                // Which control set this came from. Two control
                                // sets can hold caches naming the same binary;
                                // without this the timeline shows one execution
                                // twice with nothing to tell the rows apart.
                                "control_set": cs_name,
                            }).to_string(),
                        }),
                    )
                    .with_parent(parsed.id);

                    artifacts.push(parsed);
                    artifacts.push(timeline);
                } else {
                    artifacts.push(parsed);
                }
            }

            // Every record from this cache carries what the walk over it missed,
            // so a shortened execution list can never present as the whole of
            // the machine's history.
            if !parse.is_complete() {
                warn!(
                    "ShimcacheParser: AppCompatCache in {} walked incompletely \
                     (cap_reached={}, stopped_early={}, undecodable={})",
                    cs_name, parse.cap_reached, parse.stopped_early, parse.undecodable_records
                );
                for a in &mut artifacts {
                    stamp_cache_walk(&mut a.metadata, &parse);
                }
            }

            all_artifacts.extend(artifacts);
        }
    }

    if all_artifacts.is_empty() {
        if key_errors > 0 {
            // The navigation itself lost nodes, so "no AppCompatCache here" is
            // not something this hive supports saying.
            return Err(ParseFailure::HiveUnreadable(format!(
                "{} key or value nodes could not be read while looking for AppCompatCache",
                key_errors
            )));
        }
        return Err(ParseFailure::CacheNotFound);
    }
    Ok(all_artifacts)
}

/// Record the state of one AppCompatCache value that produced no entries, or
/// whose format was not recognised.
fn cache_status_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    control_set: &str,
    value_bytes: usize,
    version: Option<AppCompatCacheVersion>,
    entries_decoded: usize,
    unrecognised: Option<&str>,
) -> Artifact {
    let mut metadata = json!({
        "type": "ShimcacheParseStatus",
        "record_type": "shimcache_parse_status",
        "name": format!("AppCompatCache in {} (no entries decoded)", control_set),
        "control_set": control_set,
        "value_bytes": value_bytes,
        "entries_decoded": entries_decoded,
        "format_version": version.map(|v| format!("{:?}", v)),
        "message": "An AppCompatCache value is present in this ControlSet but no execution \
                    entries were decoded from it; that is not evidence that nothing ran.",
    });
    if let Some(reason) = unrecognised {
        if let Some(map) = metadata.as_object_mut() {
            map.insert("format_status".into(), json!(reason));
            add_incomplete_reason(
                map,
                seance_core::io::IncompleteReason::UnresolvedStructure.as_str(),
            );
            map.insert("inventory_incomplete".into(), json!(true));
            map.insert(
                "inventory_incomplete_reason".into(),
                json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
            );
        }
    }
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
}

/// Navigate the hive to find AppCompatCache binary value.
/// The value "AppCompatCache" is under:
///   {ControlSet}\Control\Session Manager\AppCompatCache (the value name)
/// The KEY path is: {ControlSet}\Control\Session Manager
fn navigate_to_appcompat_cache(
    root: &seance_hive::KeyNode<'_>,
    control_set: &str,
    errors: &mut u64,
) -> Option<Vec<u8>> {
    let cs_key = find_subkey(root, control_set, errors)?;
    let control_key = find_subkey(&cs_key, "Control", errors)?;
    let session_mgr = find_subkey(&control_key, "Session Manager", errors)?;

    // The value "AppCompatCache" is directly under "Session Manager"
    if let Some(val_data) = read_value(&session_mgr, "AppCompatCache", errors) {
        return Some(val_data);
    }

    // Fallback: some tools show it under an "AppCompatCache" subkey
    if let Some(appcompat_key) = find_subkey(&session_mgr, "AppCompatCache", errors) {
        if let Some(val_data) = read_value(&appcompat_key, "AppCompatCache", errors) {
            return Some(val_data);
        }
    }

    // Fallback: "AppCompatibility" key
    if let Some(compat_key) = find_subkey(&session_mgr, "AppCompatibility", errors) {
        if let Some(val_data) = read_value(&compat_key, "AppCompatCache", errors) {
            return Some(val_data);
        }
    }

    None
}

/// Helper: navigate from Session Manager to find the AppCompatCache value
/// trying both "AppCompatCache" key and "AppCompatibility" key patterns.
///
/// `errors` counts key nodes the hive parser refused. A refused node can be the
/// ControlSet holding the cache, so "not found" and "not readable" must not be
/// the same answer.
fn find_subkey<'a>(
    parent: &'a seance_hive::KeyNode<'a>,
    name: &str,
    errors: &mut u64,
) -> Option<seance_hive::KeyNode<'a>> {
    match parent.subkeys() {
        Some(Ok(subkeys)) => {
            // An `ri` sublist that would not read may be the one holding the
            // ControlSet; it is counted, not skipped (HIVE-002).
            *errors += subkeys.unresolved_sublists().len() as u64;
            for key in subkeys {
                let key = match key {
                    Ok(k) => k,
                    Err(_) => {
                        *errors += 1;
                        continue;
                    }
                };
                match key.name() {
                    Ok(key_name) => {
                        if key_name.to_string().eq_ignore_ascii_case(name) {
                            return Some(key);
                        }
                    }
                    Err(_) => *errors += 1,
                }
            }
        }
        Some(Err(_)) => *errors += 1,
        None => {}
    }
    None
}

fn read_value(
    key: &seance_hive::KeyNode<'_>,
    value_name: &str,
    errors: &mut u64,
) -> Option<Vec<u8>> {
    match key.values() {
        Some(Ok(values)) => {
            for value in values {
                let value = match value {
                    Ok(v) => v,
                    Err(_) => {
                        *errors += 1;
                        continue;
                    }
                };
                match value.name() {
                    Ok(vname) => {
                        if vname.to_string().eq_ignore_ascii_case(value_name) {
                            match value.data().ok().and_then(|d| d.into_vec().ok()) {
                                Some(bytes) => return Some(bytes),
                                None => *errors += 1,
                            }
                        }
                    }
                    Err(_) => *errors += 1,
                }
            }
        }
        Some(Err(_)) => *errors += 1,
        None => {}
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::artifact::Artifact;
    use seance_core::module::ForensicsModule;
    use std::sync::Arc;

    /// HUNT-277. A shadow-copy prior version of the SYSTEM hive is opened under
    /// its original name, everything it yields repeats the snapshot identity,
    /// and a `ParsedRecord` that is not a prior version is not read. SYNTHETIC:
    /// a `regf` header with nothing behind it, so the record is the failure
    /// status a rejected hive produces; no real evidence is graded.
    #[test]
    fn a_shadow_copy_prior_version_is_parsed_and_stamped() {
        use seance_core::data_source::ByteSliceDataSource;

        let hive = || {
            let mut data = vec![0u8; 4096];
            data[0..4].copy_from_slice(b"regf");
            Arc::new(ByteSliceDataSource::new(data))
        };
        assert!(ShimcacheParser
            .subscribes_to()
            .contains(&ArtifactType::ParsedRecord));

        let prior = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(hive()),
            json!({
                "type": "VssPriorVersion",
                "name": "SYSTEM [shadow copy 2015-03-23T00:00:00Z]",
                "file_name": "SYSTEM",
                "is_snapshot_version": true,
                "snapshot_label": "SHADOW COPY VERSION, not the live volume",
                "vss_snapshot_id": "snap-1",
                "vss_creation_time": "2015-03-23T00:00:00Z",
                "vss_stack_position": 0,
            }),
        );
        let out = ShimcacheParser.process(&prior).unwrap();
        assert_eq!(out.len(), 1, "{out:#?}");
        assert_eq!(out[0].metadata["is_snapshot_version"], json!(true));
        assert_eq!(out[0].metadata["vss_snapshot_id"], json!("snap-1"));

        let plain = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(hive()),
            json!({ "type": "SomethingElse", "name": "SYSTEM" }),
        );
        assert!(ShimcacheParser.process(&plain).unwrap().is_empty());

        let live = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(hive()),
            json!({ "name": "SYSTEM" }),
        );
        let live = ShimcacheParser.process(&live).unwrap();
        assert_eq!(live.len(), 1);
        assert!(live[0].metadata.get("is_snapshot_version").is_none());
    }

    #[test]
    fn test_non_system_hive_skipped() {
        use seance_core::data_source::ByteSliceDataSource;

        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(b"regf");

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(data))),
            json!({ "name": "NTUSER.DAT" }),
        );

        let parser = ShimcacheParser;
        let results = parser.process(&artifact).unwrap();
        assert!(results.is_empty(), "Non-SYSTEM hive should be skipped");
    }

    /// A SYSTEM hive the hive parser rejects must say so. Returning nothing is
    /// indistinguishable from a machine on which no program ever ran.
    #[test]
    fn unreadable_system_hive_emits_status_record() {
        use seance_core::data_source::ByteSliceDataSource;

        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(b"regf");

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(data))),
            json!({ "name": "SYSTEM" }),
        );

        let results = ShimcacheParser.process(&artifact).unwrap();
        assert_eq!(
            results.len(),
            1,
            "an unreadable SYSTEM hive must report itself"
        );
        let m = &results[0].metadata;
        assert_eq!(m["record_type"], "registry_hive_parse_status");
        assert_eq!(m["parse_failed"], json!(true));
        assert_eq!(m["content_incomplete"], json!(true));
        assert!(m["content_incomplete_reason"]
            .as_str()
            .unwrap()
            .contains("unresolved_structure"));
    }

    /// The production order in `process`: the AppCompatCache walk stamps its
    /// reason while parsing, and the hive's own recovery state is stamped over
    /// the same records afterwards. A capped cache read out of a hive that was
    /// not loaded in full has two separate limits, and an examiner needs both —
    /// "the cache stopped at its entry cap" and "the hive was not read in full"
    /// call for different follow-up. The hive stamp used to overwrite the walk's
    /// reason, leaving only the second.
    #[test]
    fn the_hive_stamp_does_not_erase_the_cache_walks_own_reason() {
        let parse = format::CacheParse {
            entries: Vec::new(),
            cap_reached: true,
            stopped_early: false,
            undecodable_records: 0,
            declared_entries: Some(1024),
        };
        let recovery = hive_state::HiveRecoveryState {
            dirty: false,
            logs_found: Vec::new(),
            bytes_read: 1024,
            declared_bytes: 4096,
        };

        let mut metadata = json!({ "type": "ShimcacheEntry" });
        stamp_cache_walk(&mut metadata, &parse);
        hive_state::stamp(&mut metadata, &recovery);

        let reason = metadata["content_incomplete_reason"].as_str().unwrap();
        assert!(
            reason.split('+').any(|r| r == "cap_reached"),
            "the cache walk's reason must survive the hive stamp: {reason}"
        );
        assert!(
            reason.split('+').any(|r| r == "hive_not_read_in_full"),
            "the hive's own reason must be recorded too: {reason}"
        );
        assert_eq!(metadata["content_incomplete"], json!(true));
        assert_eq!(metadata["hive_truncated"], json!(true));
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
        let out = ShimcacheParser.process(&art);
        assert!(
            matches!(out, Err(seance_core::module::ModuleError::IoError(_))),
            "an unreadable header must be an error, got {out:?}"
        );
    }
}
