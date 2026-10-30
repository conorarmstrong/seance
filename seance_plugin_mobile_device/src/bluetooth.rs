//! What the phone had paired with, and when it last saw it.
//!
//! `/data/misc/bluedroid/bt_config.conf` is the Bluetooth stack's own record of
//! every device this phone remembers: the address, the name it advertised, the
//! services it offered, the link key that secures the bond, and — for a device
//! seen since the stack started keeping them — when it was last seen.
//!
//! It answers a question nothing else on the device answers: **what physical
//! things has this phone been near, and when**. A car, a watch, a speaker, a
//! skimmer. The file's own order matters too: Android appends a device when it
//! is first remembered, so the first section is the earliest pairing — the only
//! thing that answers "which device was connected first" for an entry that
//! carries no timestamp at all.
//!
//! **The link key is not copied.** It secures the bond and decrypts that
//! device's traffic; its presence and type are findings, its value is a secret,
//! and writing it into artifact metadata would put it in the search index and
//! in every export drawn from the case. The record names the file it is in, so
//! an examiner who needs the key knows exactly where to get it.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;

/// Ceiling on the file. A phone with a hundred remembered devices is a large
/// one and its config is still tens of kilobytes.
const MAX_BYTES: usize = 4 * 1024 * 1024;

/// Is this the Bluetooth stack's config, or its backup?
pub fn is_bt_config(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "bt_config.conf" || lower == "bt_config.bak"
}

/// Reads `bt_config.conf` into pairings and device facts.
#[derive(Debug, Default)]
pub struct AndroidBluetoothParser;

impl AndroidBluetoothParser {
    pub fn new() -> Self {
        Self
    }
}

/// Does this section header name a Bluetooth address?
fn is_mac(section: &str) -> bool {
    let parts: Vec<&str> = section.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// One `[section]` of the config, as key/value pairs in file order.
struct Section {
    name: String,
    values: Vec<(String, String)>,
}

fn parse_sections(text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(Section {
                name: name.to_string(),
                values: Vec::new(),
            });
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if let Some(section) = out.last_mut() {
                section
                    .values
                    .push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    out
}

fn value<'a>(section: &'a Section, key: &str) -> Option<&'a str> {
    section
        .values
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

impl ForensicsModule for AndroidBluetoothParser {
    fn id(&self) -> &str {
        "plugin.mobile.android_bluetooth"
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
        if !is_bt_config(name) {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(name);

        // Looped: one `read_at` may answer only part of the file, and the
        // pairings after that point were simply absent (HUNT-188).
        let size = data.size();
        let buf = seance_core::io::read_capped(data.as_ref(), MAX_BYTES as u64);
        let read = buf.len() as u64;
        // Either way the pairing list is a prefix of the file's, and every
        // record says so and why: this parser's ceiling (`cap_reached`) or a
        // source that delivered less than it declared (`short_read`).
        let shortfall = if read < size.min(MAX_BYTES as u64) {
            Some((
                IncompleteReason::ShortRead,
                format!(
                    "only {read} of this file's {size} bytes could be read, so devices \
                     remembered after that point are not listed"
                ),
            ))
        } else if size > MAX_BYTES as u64 {
            Some((
                IncompleteReason::CapReached,
                format!(
                    "this file is {size} bytes and the read stops at the {MAX_BYTES}-byte \
                     ceiling, so devices remembered after that point are not listed"
                ),
            ))
        } else {
            None
        };
        let text = String::from_utf8_lossy(&buf);
        let sections = parse_sections(&text);

        // Named like the file and shaped like something else: not claimed. The
        // adapter section or at least one address-shaped section is what makes
        // this the Bluetooth stack's config rather than any other INI.
        let looks_right = sections
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case("Adapter") || is_mac(&s.name));
        if !looks_right {
            // Named like the file and too little of it read to tell: saying
            // nothing would leave the device's pairing history silent about the
            // one file that holds it.
            if let Some((reason, detail)) = shortfall {
                return Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "MobileDeviceInfo",
                        "platform": "android",
                        "subtype": "bluetooth_config_unidentified",
                        "name": "Android Bluetooth config, not read in full",
                        "source_file": path,
                        "source_kind": "android_bluetooth",
                        "facts": {},
                        "fact_sources": {},
                        CONTENT_INCOMPLETE: true,
                        CONTENT_INCOMPLETE_REASON: reason.as_str(),
                        "content_incomplete_detail": format!(
                            "{detail}; no adapter or device section is in what was read, so \
                             whether this file holds the phone's pairings could not be established"
                        ),
                    }),
                )
                .with_parent(artifact.id)]);
            }
            return Ok(Vec::new());
        }

        let mut produced = Vec::new();
        let mut order = 0usize;
        for section in &sections {
            if section.name.eq_ignore_ascii_case("Adapter") {
                // The phone's own radio, not something it paired with. Its
                // address is a device fact, which is where an examiner looks
                // for it — and it corroborates the one in settings_secure.xml.
                if let Some(address) = value(section, "Address") {
                    produced.push(
                        Artifact::new(
                            artifact.case_id,
                            ArtifactType::ParsedRecord,
                            None,
                            json!({
                                "type": "MobileDeviceInfo",
                                "platform": "android",
                                "name": "Android device facts from bt_config.conf",
                                "source_file": path,
                                "source_kind": "android_bluetooth",
                                "facts": {"bluetooth_address": address},
                                "fact_sources": {"bluetooth_address": "Adapter.Address"},
                            }),
                        )
                        .with_parent(artifact.id),
                    );
                }
                continue;
            }
            if !is_mac(&section.name) {
                continue;
            }

            let mut metadata = serde_json::Map::new();
            metadata.insert("type".into(), json!("BluetoothPairing"));
            metadata.insert("platform".into(), json!("android"));
            metadata.insert("address".into(), json!(section.name));
            metadata.insert("source_file".into(), json!(path));
            // The file's order is evidence in its own right.
            metadata.insert("order".into(), json!(order));
            let device_name = value(section, "Name");
            metadata.insert(
                "name".into(),
                json!(match device_name {
                    Some(n) => format!("{n} ({})", section.name),
                    None => section.name.clone(),
                }),
            );
            if let Some(n) = device_name {
                metadata.insert("device_name".into(), json!(n));
            }
            match value(section, "Timestamp").and_then(|t| t.parse::<i64>().ok()) {
                Some(secs) => {
                    metadata.insert("last_seen_recorded".into(), json!(true));
                    if let Some(dt) = chrono::DateTime::from_timestamp(secs, 0) {
                        metadata.insert("last_seen".into(), json!(dt.to_rfc3339()));
                    }
                }
                // Absent, and left absent: a date invented here would put a
                // pairing on the timeline that the phone never recorded.
                None => {
                    metadata.insert("last_seen_recorded".into(), json!(false));
                }
            }
            for (key, field) in [
                ("DevClass", "device_class"),
                ("DevType", "device_type"),
                ("Manufacturer", "manufacturer_id"),
                ("AddrType", "address_type"),
                ("LinkKeyType", "link_key_type"),
            ] {
                if let Some(v) = value(section, key).and_then(|v| v.parse::<i64>().ok()) {
                    metadata.insert(field.into(), json!(v));
                }
            }
            // Presence, never the value.
            metadata.insert(
                "link_key_present".into(),
                json!(value(section, "LinkKey").is_some()),
            );
            if let Some(services) = value(section, "Service") {
                let list: Vec<&str> = services.split_whitespace().collect();
                metadata.insert("services".into(), json!(list));
            }

            produced.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    serde_json::Value::Object(metadata),
                )
                .with_parent(artifact.id),
            );
            order += 1;
        }

        if let Some((reason, detail)) = shortfall {
            for record in &mut produced {
                if let Some(object) = record.metadata.as_object_mut() {
                    object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
                    object.insert(
                        CONTENT_INCOMPLETE_REASON.to_string(),
                        json!(reason.as_str()),
                    );
                    object.insert("content_incomplete_detail".to_string(), json!(detail));
                }
            }
        }
        Ok(produced)
    }
}
