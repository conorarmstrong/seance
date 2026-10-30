//! Android settings: the device's name, and how far its clock can be trusted.
//!
//! `/data/system/users/<id>/settings_{global,secure,system}.xml` hold the
//! settings the framework serves through `Settings.Global` / `Settings.Secure`.
//! Three kinds of fact in them belong on a device summary:
//!
//! * **what the device calls itself** — `device_name`, `bluetooth_name`, and the
//!   `android_id` that identifies it to Google;
//! * **whether the clock was its own** — `auto_time` and `auto_time_zone`. A
//!   device whose clock was set by hand is a device whose every timestamp is an
//!   assertion by whoever set it, and that belongs beside the timestamps rather
//!   than in a file nobody opens;
//! * **what it was allowed to run** — `adb_enabled`,
//!   `development_settings_enabled`, `install_non_market_apps`.
//!
//! Android 12 and later write these as Android Binary XML, so both encodings are
//! read and the record says which it found.

use std::borrow::Cow;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_xml_util::{abx, XmlGuard};
use serde_json::json;

/// Ceiling on a settings file. The largest of these on a real device is a few
/// hundred kilobytes.
const MAX_SETTINGS_BYTES: usize = 8 * 1024 * 1024;

/// Settings this build reads, and the fact each becomes.
///
/// A setting absent from a device is absent from the record: a default invented
/// here would be a statement about Android, not about this phone.
const SETTINGS: &[(&str, &str)] = &[
    ("device_name", "device_name"),
    ("bluetooth_name", "bluetooth_name"),
    ("android_id", "android_id"),
    ("bluetooth_address", "bluetooth_address"),
    ("adb_enabled", "adb_enabled"),
    ("development_settings_enabled", "developer_options_enabled"),
    ("install_non_market_apps", "sideloading_allowed"),
    ("auto_time", "clock_set_automatically"),
    ("auto_time_zone", "time_zone_set_automatically"),
    ("location_mode", "location_mode"),
    ("user_setup_complete", "user_setup_complete"),
];

/// Is this one of the settings files the framework writes?
pub fn is_settings_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "settings_global.xml" | "settings_secure.xml" | "settings_system.xml"
    )
}

/// Reads Android settings files into device facts.
#[derive(Debug, Default)]
pub struct AndroidSettingsParser;

impl AndroidSettingsParser {
    pub fn new() -> Self {
        Self
    }
}

/// One `<setting name= value= />` pair, where both were readable.
fn setting_pair(element: &BytesStart<'_>, guard: &mut XmlGuard) -> Option<(String, String)> {
    let mut name = None;
    let mut value = None;
    for attr in guard.attributes(element) {
        let key = attr.key.as_ref().to_vec();
        let Ok(text) = attr.unescape_value() else {
            continue;
        };
        match key.as_slice() {
            b"name" => name = Some(text.into_owned()),
            b"value" => value = Some(text.into_owned()),
            _ => {}
        }
    }
    Some((name?, value?))
}

impl ForensicsModule for AndroidSettingsParser {
    fn id(&self) -> &str {
        "plugin.mobile.android_settings"
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
        if !is_settings_file(name) {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let declared = data.size() as usize;
        let want = declared.min(MAX_SETTINGS_BYTES);
        let mut buf = vec![0u8; want];
        let read = data
            .read_at(0, &mut buf)
            .map_err(|e| ModuleError::ParsingError(format!("reading {name}: {e}")))?;
        buf.truncate(read);
        let short = declared > MAX_SETTINGS_BYTES || read < want;

        let (text, encoding, abx_error) = if abx::is_abx(&buf) {
            let decoded = abx::decode(&buf);
            (
                Cow::Owned(abx::render_text_xml(&decoded.document)),
                "abx",
                decoded.error.map(|e| e.to_string()),
            )
        } else {
            (String::from_utf8_lossy(&buf), "text", None)
        };

        let mut reader = Reader::from_str(&text);
        let mut xml_buf = Vec::new();
        let mut guard = XmlGuard::default();
        let mut found = serde_json::Map::new();
        let mut sources = serde_json::Map::new();
        let mut settings_seen = 0usize;
        let mut stopped_early = false;

        loop {
            match reader.read_event_into(&mut xml_buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    if e.name().as_ref() == b"setting" {
                        settings_seen += 1;
                        if let Some((key, value)) = setting_pair(&e, &mut guard) {
                            if value.is_empty() {
                                continue;
                            }
                            if let Some((_, fact)) =
                                SETTINGS.iter().find(|(setting, _)| *setting == key)
                            {
                                found.insert((*fact).to_string(), json!(value));
                                sources.insert((*fact).to_string(), json!(key));
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(_) => {
                    stopped_early = true;
                    break;
                }
                _ => {}
            }
            xml_buf.clear();
        }

        // Nothing that looks like a settings document: the name matched and the
        // content did not, so this file is not claimed.
        if settings_seen == 0 && !short && !stopped_early {
            return Ok(Vec::new());
        }

        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(name);

        let mut metadata = json!({
            "type": "MobileDeviceInfo",
            "platform": "android",
            "name": format!("Android device facts from {name}"),
            "source_file": path,
            "source_kind": "android_settings",
            "encoding": encoding,
            "settings_read": settings_seen,
            "facts": found,
            "fact_sources": sources,
        });

        if short || stopped_early || abx_error.is_some() {
            let object = metadata.as_object_mut().expect("object literal");
            let (reason, detail) = if short {
                (
                    IncompleteReason::ShortRead,
                    format!("only {read} byte(s) of this settings file were acquired"),
                )
            } else if let Some(err) = abx_error.as_ref() {
                (
                    IncompleteReason::UnresolvedStructure,
                    format!("the ABX document could not be decoded to its end: {err}"),
                )
            } else {
                (
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the settings document could not be parsed past setting {settings_seen}"
                    ),
                )
            };
            object.insert(CONTENT_INCOMPLETE.to_string(), json!(true));
            object.insert(
                CONTENT_INCOMPLETE_REASON.to_string(),
                json!(reason.as_str()),
            );
            object.insert(
                "content_incomplete_detail".to_string(),
                json!(format!(
                    "{detail}; settings after that point are not in this record, so a fact \
                     missing here may be one that was never reached"
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
