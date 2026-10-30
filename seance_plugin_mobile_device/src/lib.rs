//! Whose phone is this?
//!
//! An examiner opening a mobile exhibit asks that first, and until now Séance
//! could not answer it on one screen: `system_info` compiles Windows registry
//! hives, and on an Android or iOS image it returns empty. The Pixel 7a's model,
//! serial, build and Google account were all present in the evidence and
//! indexed, and reachable only by searching raw files (HUNT-079).
//!
//! This module reads the Android property files — `build.prop` and its siblings,
//! the `key=value` text the framework itself reads `ro.*` properties from — and
//! emits one `MobileDeviceInfo` record per file.
//!
//! **Every fact names the file it came from, and nothing is reconciled here.** A
//! device has several property files (`/system/build.prop`,
//! `/vendor/build.prop`, `/odm/etc/build.prop`, `default.prop`) and they can
//! disagree — a vendor image reflashed over a system image is exactly the kind of
//! thing an examiner needs to see rather than have averaged away. One record per
//! file preserves the disagreement; the device-facts surface shows it.
//!
//! The SQLite sources in this crate ([`accounts`], [`telephony`]) carry the
//! schema-drift defence of [`seance_sqlite_util::stale`]: each store's `PRAGMA
//! user_version` is compared against the version it was validated against on a
//! real database (`accounts_de.db` 3, `accounts_ce.db` 10, `telephony.db`
//! 1703944, all from the android2022 image), and every column read is resolved
//! through a candidate list before a query is written. A store outside that
//! range, or one whose required column no candidate matched, is still parsed as
//! far as it can be and a `ParserStaleWarning` record is appended. See
//! [`schema_support`].

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;

/// Ceiling on a property file. A real `build.prop` is a few kilobytes; this
/// bounds a hostile or misnamed file without capping any genuine one.
const MAX_PROPERTY_BYTES: usize = 1024 * 1024;

/// Ceiling on how many properties are carried into a record, so a file that is
/// all `ro.*` lines cannot make one enormous artifact.
const MAX_PROPERTIES: usize = 4_000;

/// Reads Android property files into device facts.
#[derive(Debug, Default)]
pub struct AndroidPropertiesParser;

impl AndroidPropertiesParser {
    pub fn new() -> Self {
        Self
    }
}

/// Is this one of the files the Android property service reads?
///
/// Matched on the file name, and on the name alone: these files have no magic,
/// and their content is `key=value` text that a great many other files share.
/// A name-only match is corroborated by the content check in `parse`, which
/// requires at least one `ro.` property before it claims the file.
pub fn is_property_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "build.prop" | "default.prop" | "prop.default" | "vendor.prop" | "odm.prop"
    )
}

/// One property file's contents, as read.
#[derive(Debug, Default)]
pub struct Properties {
    /// Every `key=value` pair, in key order.
    pub values: BTreeMap<String, String>,
    /// Lines that were not `key=value` and not a comment.
    pub unparsed_lines: usize,
    /// Whether the read stopped at [`MAX_PROPERTY_BYTES`].
    pub truncated: bool,
    /// Whether the property cap stopped the collection.
    pub capped: bool,
}

/// Parse the `key=value` text of a property file.
///
/// Comments (`#`) and blank lines are skipped. A line with no `=` is counted
/// rather than dropped silently: a property file this parser only half
/// understands must not read as a device with fewer properties.
pub fn parse_properties(bytes: &[u8]) -> Properties {
    let mut out = Properties::default();
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            out.unparsed_lines += 1;
            continue;
        };
        if out.values.len() >= MAX_PROPERTIES {
            out.capped = true;
            break;
        }
        out.values
            .insert(key.trim().to_string(), value.trim().to_string());
    }
    out
}

/// The device facts this build reads out of Android properties, in the order a
/// device summary presents them.
///
/// Each is a list of candidate keys, most authoritative first. `ro.product.*`
/// moved under per-partition prefixes (`ro.product.system.*`,
/// `ro.product.vendor.*`) in Android 10, and the framework itself falls back
/// through them, so reading only the bare key returns nothing on a modern
/// device.
const FACTS: &[(&str, &[&str])] = &[
    (
        "manufacturer",
        &[
            "ro.product.manufacturer",
            "ro.product.system.manufacturer",
            "ro.product.vendor.manufacturer",
        ],
    ),
    (
        "model",
        &[
            "ro.product.model",
            "ro.product.system.model",
            "ro.product.vendor.model",
        ],
    ),
    ("device", &["ro.product.device", "ro.product.system.device"]),
    (
        "product_name",
        &["ro.product.name", "ro.product.system.name"],
    ),
    (
        "android_version",
        &[
            "ro.build.version.release",
            "ro.system.build.version.release",
        ],
    ),
    ("sdk_level", &["ro.build.version.sdk"]),
    ("security_patch", &["ro.build.version.security_patch"]),
    ("build_id", &["ro.build.id", "ro.system.build.id"]),
    (
        "build_fingerprint",
        &["ro.build.fingerprint", "ro.system.build.fingerprint"],
    ),
    ("build_display_id", &["ro.build.display.id"]),
    ("build_date_utc", &["ro.build.date.utc"]),
    ("build_type", &["ro.build.type"]),
    ("build_tags", &["ro.build.tags"]),
    ("serial_number", &["ro.serialno", "ro.boot.serialno"]),
    ("hardware", &["ro.hardware", "ro.boot.hardware"]),
    ("bootloader", &["ro.bootloader"]),
    ("cpu_abi", &["ro.product.cpu.abi", "ro.product.cpu.abilist"]),
    ("locale", &["ro.product.locale"]),
    ("timezone", &["persist.sys.timezone"]),
    ("encryption_state", &["ro.crypto.state"]),
    ("encryption_type", &["ro.crypto.type"]),
    ("verified_boot_state", &["ro.boot.verifiedbootstate"]),
];

/// The fact, and which key it was read from.
fn fact_from(props: &Properties, keys: &[&str]) -> Option<(String, String)> {
    for key in keys {
        if let Some(value) = props.values.get(*key) {
            if !value.is_empty() {
                return Some((value.clone(), (*key).to_string()));
            }
        }
    }
    None
}

/// The record for a file named like a property file that was too short to
/// identify.
///
/// Its name says it may carry the device's identity and its bytes cannot
/// confirm it. Saying nothing would leave a device summary silent about the one
/// file that would have filled it in.
///
/// `short` says which shortfall it was: the source delivering less than it
/// declared (`short_read`), or this parser's byte ceiling (`cap_reached`).
fn unidentified_property_file(
    artifact: &Artifact,
    path: &str,
    read: usize,
    short: bool,
) -> Artifact {
    let (reason, how) = if short {
        (IncompleteReason::ShortRead, "were acquired")
    } else {
        (
            IncompleteReason::CapReached,
            "were read before the parser's byte ceiling",
        )
    };
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "MobileDeviceInfo",
            "platform": "android",
            "subtype": "properties_unidentified",
            "name": "Android property file, not read in full",
            "source_file": path,
            "source_kind": "android_properties",
            "facts": {},
            "fact_sources": {},
            CONTENT_INCOMPLETE: true,
            CONTENT_INCOMPLETE_REASON: reason.as_str(),
            "content_incomplete_detail": format!(
                "only {read} byte(s) of this file {how}, and none of them carry an \
                 `ro.` property, so whether it holds this device's identity could not be \
                 established from what is here"
            ),
        }),
    )
    .with_parent(artifact.id)
}

impl ForensicsModule for AndroidPropertiesParser {
    fn id(&self) -> &str {
        "plugin.mobile.android_properties"
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
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_property_file(name) {
            return Ok(Vec::new());
        }
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

        // Looped: a windowed source may answer a few bytes per call, and one
        // `read_at` took only the first of them (HUNT-188).
        let size = data.size();
        let buf = seance_core::io::read_capped(data.as_ref(), MAX_PROPERTY_BYTES as u64);
        let read = buf.len();
        let want = size.min(MAX_PROPERTY_BYTES as u64) as usize;

        let mut props = parse_properties(&buf);
        // Two different shortfalls, both of which change what the record means,
        // and each gets its own reason: this parser's ceiling stopping the read
        // is `cap_reached`; the source delivering less than it declared is
        // `short_read`.
        let short = read < want;
        let over_ceiling = size > MAX_PROPERTY_BYTES as u64;
        props.truncated = short || over_ceiling;

        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(name);

        // A name-only match has to be corroborated: `build.prop` is a common
        // enough name outside Android, and a file of unrelated `key=value` text
        // claimed as a device's identity would put invented facts on a device
        // summary.
        if !props.values.keys().any(|k| k.starts_with("ro.")) {
            if props.truncated {
                // Named like a property file, and too little of it was acquired
                // to tell. Returning nothing here would leave a device summary
                // silent about a file that may well hold its identity.
                return Ok(vec![unidentified_property_file(
                    artifact, path, read, short,
                )]);
            }
            debug!("{name} has no ro.* properties; not claiming it as Android device facts");
            return Ok(Vec::new());
        }

        let mut facts = serde_json::Map::new();
        let mut sources = serde_json::Map::new();
        for (fact, keys) in FACTS {
            if let Some((value, key)) = fact_from(&props, keys) {
                facts.insert((*fact).to_string(), json!(value));
                sources.insert((*fact).to_string(), json!(key));
            }
        }

        let mut metadata = json!({
            "type": "MobileDeviceInfo",
            "platform": "android",
            "name": format!("Android device facts from {name}"),
            "source_file": path,
            "source_kind": "android_properties",
            "properties_read": props.values.len(),
            "unparsed_lines": props.unparsed_lines,
            "facts": facts,
            // Which property each fact was read from. An examiner asked to
            // stand over "the model is Pixel 7a" needs the key as much as the
            // value, and the keys moved between Android versions.
            "fact_sources": sources,
        });

        if props.truncated || props.capped {
            let reason = if short {
                IncompleteReason::ShortRead
            } else {
                IncompleteReason::CapReached
            };
            let object = metadata.as_object_mut().expect("object literal");
            object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
            object.insert(
                CONTENT_INCOMPLETE_REASON.to_string(),
                json!(reason.as_str()),
            );
            object.insert(
                "content_incomplete_detail".to_string(),
                json!(if short {
                    format!(
                        "only the first {read} byte(s) of this property file could be read, \
                         so properties after that point are not in this record"
                    )
                } else if over_ceiling {
                    format!(
                        "this property file is {size} bytes and the read stops at the \
                         {MAX_PROPERTY_BYTES}-byte ceiling, so properties after that point are \
                         not in this record"
                    )
                } else {
                    format!(
                        "the property cap of {MAX_PROPERTIES} stopped the read, so properties \
                         after it are not in this record"
                    )
                }),
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

pub mod accounts;
pub mod bluetooth;
mod schema_support;
pub mod settings;
pub mod telephony;

pub use accounts::AndroidAccountsParser;
pub use bluetooth::AndroidBluetoothParser;
pub use settings::AndroidSettingsParser;
pub use telephony::AndroidTelephonyParser;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_bluetooth;
#[cfg(test)]
mod tests_short_reads;
#[cfg(test)]
mod tests_sources;
