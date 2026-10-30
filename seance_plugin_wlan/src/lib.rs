#![forbid(unsafe_code)]
//! Windows wireless profiles: which networks a machine was configured to
//! join, and what it held for them (`ROADMAP` §4.3 stage 2).
//!
//! # What this reads
//!
//! `%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\{interface}\{profile}.xml`
//! — one file per configured network, written by the WLAN service. Each holds
//! the SSID, whether the network was hidden, the authentication and encryption
//! agreed, whether the machine joined it automatically, and the pre-shared key
//! either in plain text or as a DPAPI blob.
//!
//! # Why an examiner wants it
//!
//! It is a list of the places a machine has been. A wireless SSID is
//! geolocatable — the public wardriving databases map most of them to a street
//! — so a profile list places a laptop at a house, an office, a hotel and an
//! airport without a single GPS fix. It is also the strongest available
//! statement of *intent* to join: a profile with `connectionMode` `auto` means
//! the machine joined that network whenever it was in range, and somebody put
//! it there.
//!
//! # The key
//!
//! `keyMaterial` is the passphrase in plain text when `protected` is `false`,
//! which is what a profile exported with `netsh wlan export profile key=clear`
//! carries, and what some deployment tooling writes. When `protected` is
//! `true` it is a DPAPI blob: [`dpapi`] names the master key it was encrypted
//! under and exactly what recovering it would require, and this build does
//! **not** decrypt it. Both cases are reported as what they are — a record
//! that simply omitted the key would read as a profile that had none.
//!
//! # What it does not know
//!
//! **When the machine actually joined.** The XML carries no timestamps at all,
//! so no record here places a join on the timeline: the file's own timestamps
//! are the FileEntry's, and the join history lives in the
//! `Microsoft-Windows-WLAN-AutoConfig/Operational` event channel and the
//! `NetworkList` registry keys, neither of which this module reads. The macOS
//! sibling (`seance_plugin_macos_artifacts::wifi`) does carry `added_at` and
//! `last_joined`, because the plist it reads holds them; the difference is in
//! the evidence, not in the parsing, and every record here says so.

use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use seance_core::module::{ForensicsModule, InputCapability, ModuleError};
use serde_json::json;
use tracing::{debug, info};

pub mod dpapi;
pub mod profile;

/// The module's stable identifier.
pub const MODULE_ID: &str = "plugin.windows.wlan_profiles";

/// Bytes of one profile staged for parsing. A real profile is one to four
/// kilobytes; past this the file is refused with its size on the record rather
/// than read.
pub const MAX_PROFILE_BYTES: u64 = 1024 * 1024;

/// The wireless-profile parser.
pub struct WlanProfiles;

impl ForensicsModule for WlanProfiles {
    fn id(&self) -> &'static str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl WlanProfiles {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(source) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // Recognised by content, never by path: a profile exported to a
        // desktop, carved out of unallocated space or pulled from a live
        // response is the same document, and a path test would miss all three.
        let declared = source.size();
        if declared == 0 {
            return Ok(Vec::new());
        }
        let head = seance_core::io::read_capped(source.as_ref(), 4096);
        if !profile::looks_like_profile(&head) {
            return Ok(Vec::new());
        }
        let name = file_name(artifact);
        if declared > MAX_PROFILE_BYTES {
            info!(
                "WLAN profile '{}' (ID: {}) declares {} bytes, past this build's ceiling",
                name, artifact.id, declared
            );
            return Ok(vec![refusal(
                artifact,
                &name,
                IncompleteReason::CapReached,
                &format!(
                    "the file declares {declared} bytes and this build stages at most \
                     {MAX_PROFILE_BYTES} for a wireless profile; it was not parsed"
                ),
            )]);
        }
        let bytes = seance_core::io::read_capped(source.as_ref(), MAX_PROFILE_BYTES);
        let staged = bytes.len() as u64;
        debug!(
            "Reading WLAN profile '{}' (ID: {}, {} bytes)",
            name, artifact.id, staged
        );
        let parsed = match profile::parse(&bytes) {
            Some(parsed) => parsed,
            None => {
                return Ok(vec![refusal(
                    artifact,
                    &name,
                    IncompleteReason::UnresolvedStructure,
                    "the file begins as a WLAN profile and its XML could not be walked to a \
                     profile name and SSID; nothing was read from it rather than a name being \
                     guessed at",
                )])
            }
        };
        let mut record = profile_record(artifact, &name, &parsed);
        if staged < declared {
            stamp(
                &mut record.metadata,
                IncompleteReason::ShortRead,
                &format!(
                    "the file declares {declared} bytes and {staged} could be read; a profile \
                     element after the cut is not in this record"
                ),
            );
        }
        Ok(vec![record])
    }
}

/// One profile's record.
fn profile_record(artifact: &Artifact, file_name: &str, parsed: &profile::Profile) -> Artifact {
    let ssid = parsed.ssid();
    let mut m = json!({
        "type": "WifiNetwork",
        "subtype": "windows_profile",
        "platform": "windows",
        "name": format!("Wi-Fi network: {ssid}"),
        "short_desc": parsed.short_desc(),
        "ssid": ssid,
        "profile_name": parsed.profile_name,
        "source_file": file_name,
        "statement": profile::STATEMENT,
    });
    if let Some(object) = m.as_object_mut() {
        if let serde_json::Value::Object(fields) = parsed.to_json() {
            for (key, value) in fields {
                object.insert(key, value);
            }
        }
        // Where the file was found, the interface GUID is the directory above
        // it, which is how two profiles on two adapters are told apart.
        if let Some(path) = path_of(artifact) {
            object.insert("path".into(), json!(path));
            if let Some(interface) = interface_guid(&path) {
                object.insert("interface_guid".into(), json!(interface));
            }
        }
    }
    for (reason, detail) in parsed.shortfalls() {
        stamp_or_extend(&mut m, reason, &detail);
    }
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, m)
        .with_parent(artifact.id)
        .with_subtype("windows_profile")
}

/// A file that is a wireless profile and was not read. Emitted rather than
/// skipped: "there was no profile here" and "there was one and it was not
/// read" must never render the same.
fn refusal(
    artifact: &Artifact,
    file_name: &str,
    reason: IncompleteReason,
    detail: &str,
) -> Artifact {
    let m = json!({
        "type": "WifiNetworkIncomplete",
        "subtype": "windows_profile_unread",
        "platform": "windows",
        "name": format!("Wireless profile not read: {file_name}"),
        "short_desc": format!("Wireless profile '{file_name}' was not read"),
        "source_file": file_name,
        "path": path_of(artifact),
        "detail": detail,
        "content_incomplete": true,
        "content_incomplete_reason": reason.as_str(),
        "content_incomplete_detail": detail,
    });
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, m)
        .with_parent(artifact.id)
        .with_subtype("windows_profile_unread")
}

/// Write one stamp family: `content_incomplete`, its reason and its detail.
fn stamp(m: &mut serde_json::Value, reason: IncompleteReason, detail: &str) {
    if let Some(object) = m.as_object_mut() {
        object.insert("content_incomplete".into(), json!(true));
        object.insert("content_incomplete_reason".into(), json!(reason.as_str()));
        object.insert("content_incomplete_detail".into(), json!(detail));
    }
}

/// Add a stamp to a record that may already carry one. The first reason
/// stands — it is the more specific place to look — and every detail is kept,
/// because a profile can be short in more than one way at once.
fn stamp_or_extend(m: &mut serde_json::Value, reason: IncompleteReason, detail: &str) {
    let prior = m
        .get("content_incomplete_detail")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    match prior {
        Some(prior) if m.get("content_incomplete") == Some(&json!(true)) => {
            if let Some(object) = m.as_object_mut() {
                object.insert(
                    "content_incomplete_detail".into(),
                    json!(format!("{prior}; {detail}")),
                );
            }
        }
        _ => stamp(m, reason, detail),
    }
}

fn file_name(artifact: &Artifact) -> String {
    // A prior version's `name` carries the shadow-copy label.
    if let Some(value) = seance_core::shadow_copy::original_name(artifact) {
        let base = value.rsplit(['/', '\\']).next().unwrap_or(value);
        if !base.is_empty() {
            return base.to_string();
        }
    }
    for key in ["name", "file_name", "path", "source_path"] {
        if let Some(value) = artifact.metadata.get(key).and_then(|v| v.as_str()) {
            let base = value.rsplit(['/', '\\']).next().unwrap_or(value);
            if !base.is_empty() {
                return base.to_string();
            }
        }
    }
    "(unnamed)".to_string()
}

fn path_of(artifact: &Artifact) -> Option<String> {
    for key in ["path", "full_path", "source_path"] {
        if let Some(value) = artifact.metadata.get(key).and_then(|v| v.as_str()) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// The interface GUID a profile sits under, where the path shows it. Windows
/// stores one directory per wireless adapter, named by its GUID.
fn interface_guid(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = path.split(['/', '\\']).collect();
    parts.pop()?;
    let directory = parts.pop()?;
    let trimmed = directory.trim_start_matches('{').trim_end_matches('}');
    // A GUID is 36 characters of hex and hyphens; a directory that is not one
    // is not reported as an interface.
    let shaped = trimmed.len() == 36
        && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        && trimmed.matches('-').count() == 4;
    shaped.then(|| trimmed.to_ascii_lowercase())
}

/// The module, for registration.
pub fn module() -> Arc<dyn ForensicsModule> {
    Arc::new(WlanProfiles)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod lib_tests;

#[cfg(test)]
#[path = "real_profile_tests.rs"]
mod real_profile_tests;
