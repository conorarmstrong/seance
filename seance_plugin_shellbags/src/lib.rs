#![forbid(unsafe_code)]
#[cfg(test)]
mod tests;

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::module::{ForensicsModule, InputCapability, ModuleError};
use tracing::{debug, info, warn};

use seance_hive_util::hive_state;
pub mod shellbag_structs;
use shellbag_structs::ShellBagParser;

/// Upper bound on how much of a hive is buffered into RAM before parsing. A
/// mis-detected or hostile input must not OOM the worker; the registry and
/// Amcache plugins cap the same way.
const MAX_HIVE_BYTES: u64 = 512 * 1024 * 1024;

pub struct ShellBagsPlugin;

impl ForensicsModule for ShellBagsPlugin {
    fn id(&self) -> &str {
        "plugin.windows.shellbags"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            // A shadow-copy prior version only (HUNT-277).
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

impl ShellBagsPlugin {
    fn parse_hive(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let mut produced_artifacts = Vec::new();

        // A prior version's `name` carries the shadow-copy label, so the
        // file's own name is read.
        let name = seance_core::shadow_copy::original_name(artifact)
            .unwrap_or_default()
            .to_lowercase();

        // Target specific registry hives
        if !name.ends_with("usrclass.dat") && !name.ends_with("ntuser.dat") {
            return Ok(produced_artifacts);
        }

        info!("ShellBagsPlugin scanning hive: {}", name);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("ShellBags parser requires data source".to_string())
        })?;

        let buffer = seance_core::io::read_capped(data_source.as_ref(), MAX_HIVE_BYTES);

        // A hive taken from a running system keeps its most recent writes in
        // `.LOG1`/`.LOG2`. This parser reads the primary file only, so a dirty
        // hive means the newest folder-access evidence may be absent from what
        // follows. Detect it once and stamp it on every bag emitted below, so
        // "this folder was never opened" is never confused with "this hive was
        // captured before that write was flushed".
        let recovery = hive_state::inspect(artifact, &buffer);
        if recovery.evidence_pending_in_logs() {
            warn!(
                "ShellBags: hive '{}' is dirty and its transaction logs ({}) were not replayed; \
                 recent BagMRU entries may be missing",
                name,
                recovery.logs_found.join(", ")
            );
        }
        if recovery.truncated() {
            warn!(
                "ShellBags: only {} of {} bytes of hive '{}' were loaded; \
                 bags beyond that point were never examined",
                recovery.bytes_read, recovery.declared_bytes, name
            );
        }

        let hive = match seance_hive_util::open_hive(buffer.as_slice()) {
            Ok(h) => h,
            Err(e) => {
                debug!(
                    "Failed to parse hive '{}' (artifact ID: {}, size: {} bytes): {}",
                    name,
                    artifact.id,
                    buffer.len(),
                    e
                );
                // A hive that would not even open must not leave the case
                // looking like a user who opened no folders. This used to be
                // reported only when the hive was ALSO known to be short or
                // dirty, so an ordinary file named `UsrClass.dat` that is not
                // a hive produced no records and no reason — the reason went
                // to the log above (`HUNT-130`).
                produced_artifacts.push(hive_state::unreadable_artifact(
                    artifact.case_id,
                    artifact.id,
                    &name,
                    "shellbags",
                    &e.to_string(),
                    &recovery,
                ));
                return Ok(produced_artifacts);
            }
        };

        let root = hive
            .root_key_node()
            .map_err(|e| ModuleError::ParsingError(e.to_string()))?;

        // Define potential BagMRU paths
        let paths = vec![
            r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU", // UsrClass
            r"Software\Microsoft\Windows\Shell\BagMRU",                // NTUSER
            r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",          // XP
        ];

        for path in paths {
            let path_parts: Vec<&str> = path.split('\\').collect();
            let mut current_node = root;
            let mut found = true;

            for part in path_parts {
                let mut next_node = None;
                if let Some(Ok(subkeys)) = current_node.subkeys() {
                    for subkey in subkeys.flatten() {
                        // NtHiveNameString implements Display
                        if subkey
                            .name()
                            .map(|n| n.to_string())
                            .unwrap_or_default()
                            .eq_ignore_ascii_case(part)
                        {
                            next_node = Some(subkey);
                            break;
                        }
                    }
                }

                if let Some(node) = next_node {
                    current_node = node;
                } else {
                    found = false;
                    break;
                }
            }

            if found {
                info!("Found BagMRU at {}", path);
                let parser = ShellBagParser::new(artifact.case_id, artifact.id);
                let mut results = parser.parse_bag_mru(&current_node, &format!("ROOT:{}", path));
                for a in &mut results {
                    hive_state::stamp(&mut a.metadata, &recovery);
                }
                produced_artifacts.extend(results);
            }
        }

        // No bags at all out of a hive we know we did not read in the state it
        // was captured in: say so, or the case cannot tell that apart from a
        // user who genuinely browsed nothing.
        if produced_artifacts.is_empty() && recovery.incomplete() {
            produced_artifacts.push(hive_state::status_artifact(
                artifact.case_id,
                artifact.id,
                &name,
                &recovery,
            ));
        }

        Ok(produced_artifacts)
    }
}
