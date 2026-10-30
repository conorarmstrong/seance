//! The identity files of a macOS system.
//!
//! Two files answer "what machine is this?" on a Mac, and they answer different
//! halves of it. `SystemVersion.plist` states the operating system and the build
//! it was assembled from — the answer an examiner quotes when the case turns on
//! what the machine could do. `SystemConfiguration/preferences.plist` states the
//! names: the computer name a person typed, and the local host name the network
//! sees, which are not the same string and must not be shown as if they were.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;

/// Ceiling on an identity plist. `preferences.plist` on a machine with many
/// network services is tens of kilobytes; this bounds a misnamed file without
/// capping a genuine one.
const MAX_IDENTITY_BYTES: usize = 4 * 1024 * 1024;

/// Which macOS identity file a path is, if it is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacIdentityFile {
    /// `/System/Library/CoreServices/SystemVersion.plist`.
    SystemVersion,
    /// `/Library/Preferences/SystemConfiguration/preferences.plist`.
    Preferences,
}

/// Recognise a macOS identity file by its **path**.
///
/// `preferences.plist` is one of the commonest file names on a Mac — every
/// application bundle can ship one — so the path is what makes this file the
/// system's own. Matched as a suffix, so a volume prefix (`/<volume
/// UUID>/System/…`, the shape an APFS container is walked under) still matches.
pub fn mac_identity_file(path: &str) -> Option<MacIdentityFile> {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    if lower.ends_with("/system/library/coreservices/systemversion.plist") {
        return Some(MacIdentityFile::SystemVersion);
    }
    if lower.ends_with("/library/preferences/systemconfiguration/preferences.plist") {
        return Some(MacIdentityFile::Preferences);
    }
    None
}

/// The facts `SystemVersion.plist` states, and the key each is read from.
const VERSION_FACTS: &[(&str, &str)] = &[
    ("os_name", "ProductName"),
    ("os_version", "ProductVersion"),
    ("build_id", "ProductBuildVersion"),
];

/// The names `preferences.plist` states, as a path through its nested
/// dictionaries.
const NAME_FACTS: &[(&str, &[&str])] = &[
    (
        "host_name",
        &["System", "Network", "HostNames", "LocalHostName"],
    ),
    ("computer_name", &["System", "System", "ComputerName"]),
    ("dns_host_name", &["System", "System", "HostName"]),
];

/// Follow a path of dictionary keys to a string.
fn string_at<'a>(value: &'a plist::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.as_dictionary()?.get(key)?;
    }
    current.as_string()
}

/// Reads the identity files of a macOS system into host facts.
#[derive(Debug, Default)]
pub struct MacHostParser;

impl MacHostParser {
    pub fn new() -> Self {
        Self
    }
}

fn title(kind: MacIdentityFile) -> &'static str {
    match kind {
        MacIdentityFile::SystemVersion => "macOS version and build",
        MacIdentityFile::Preferences => "macOS machine names",
    }
}

fn source_kind(kind: MacIdentityFile) -> &'static str {
    match kind {
        MacIdentityFile::SystemVersion => "system_version_plist",
        MacIdentityFile::Preferences => "system_configuration_preferences",
    }
}

/// The record for an identity plist that is at the right path and could not be
/// read. Saying nothing would leave the host summary silent about the one file
/// that names the machine.
fn unread_identity_plist(
    artifact: &Artifact,
    kind: MacIdentityFile,
    path: &str,
    detail: String,
) -> Artifact {
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "HostDeviceInfo",
            "platform": "macos",
            "subtype": "identity_unread",
            "name": format!("{}, not read", title(kind)),
            "source_file": path,
            "source_kind": source_kind(kind),
            "facts": {},
            "fact_sources": {},
            CONTENT_INCOMPLETE: true,
            CONTENT_INCOMPLETE_REASON: IncompleteReason::UnresolvedStructure.as_str(),
            "content_incomplete_detail": detail,
        }),
    )
    .with_parent(artifact.id)
}

impl ForensicsModule for MacHostParser {
    fn id(&self) -> &str {
        "plugin.macos.host_facts"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .or_else(|| artifact.metadata.get("name").and_then(|v| v.as_str()))
            .unwrap_or("");
        let Some(kind) = mac_identity_file(path) else {
            return Ok(Vec::new());
        };
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let size = data.size() as usize;
        let want = size.min(MAX_IDENTITY_BYTES);
        let mut buf = vec![0u8; want];
        let read = data
            .read_at(0, &mut buf)
            .map_err(|e| ModuleError::ParsingError(format!("reading {path}: {e}")))?;
        buf.truncate(read);
        let truncated = size > MAX_IDENTITY_BYTES || read < want;

        let value = match plist::Value::from_reader(std::io::Cursor::new(&buf)) {
            Ok(value) => value,
            Err(e) => {
                debug!("{path} did not parse as a plist: {e}");
                let detail = if truncated {
                    format!(
                        "only {read} of this file's {size} byte(s) were acquired and what is \
                         here does not parse as a property list, so the machine's identity \
                         could not be read from it"
                    )
                } else {
                    format!(
                        "this file is at the path the system keeps its identity at and does \
                         not parse as a property list ({e}), so the machine's identity could \
                         not be read from it"
                    )
                };
                return Ok(vec![unread_identity_plist(artifact, kind, path, detail)]);
            }
        };

        let mut facts = serde_json::Map::new();
        let mut sources = serde_json::Map::new();
        match kind {
            MacIdentityFile::SystemVersion => {
                for (fact, key) in VERSION_FACTS {
                    if let Some(found) = string_at(&value, &[key]) {
                        facts.insert((*fact).to_string(), json!(found));
                        sources.insert((*fact).to_string(), json!(*key));
                    }
                }
            }
            MacIdentityFile::Preferences => {
                for (fact, keys) in NAME_FACTS {
                    if let Some(found) = string_at(&value, keys) {
                        facts.insert((*fact).to_string(), json!(found));
                        sources.insert((*fact).to_string(), json!(keys.join(".")));
                    }
                }
            }
        }

        if facts.is_empty() {
            let detail = format!(
                "this property list parsed and states none of the keys the machine's identity \
                 is kept under, so nothing about the host was read from it ({read} byte(s) read)"
            );
            return Ok(vec![unread_identity_plist(artifact, kind, path, detail)]);
        }

        let mut metadata = json!({
            "type": "HostDeviceInfo",
            "platform": "macos",
            "name": title(kind),
            "source_file": path,
            "source_kind": source_kind(kind),
            "facts": facts,
            "fact_sources": sources,
        });
        if truncated {
            let object = metadata.as_object_mut().expect("object literal");
            object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
            object.insert(
                CONTENT_INCOMPLETE_REASON.to_string(),
                json!(IncompleteReason::ShortRead.as_str()),
            );
            object.insert(
                "content_incomplete_detail".to_string(),
                json!(format!(
                    "only the first {read} byte(s) of this file were read, so anything after \
                     that point is not in this record"
                )),
            );
        }

        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(artifact.id)])
    }
}

#[cfg(test)]
#[path = "tests_macos.rs"]
mod tests;
