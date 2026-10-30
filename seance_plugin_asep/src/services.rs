//! Services and drivers: the `SYSTEM` hive's `ControlSet***\Services` tree.
//!
//! A service key is spread over several values (`Start`, `Type`, `ImagePath`,
//! `ObjectName`, `DisplayName`) plus a `Parameters\ServiceDll` subkey, so the
//! registry scan accumulates them per service key and this module turns each
//! accumulation into one entry.
//!
//! Two things here decide whether the report is trustworthy. First, the start
//! type: `0` is "load during kernel initialisation" and `4` is "disabled", so a
//! corrupt or missing `Start` value must be reported as unreadable rather than
//! defaulted — defaulting to `0` would invent a boot-start driver, and
//! defaulting to `4` would hide a real one. Second, every control set is
//! reported separately: `ControlSet001` and `ControlSet002` can disagree, and
//! collapsing them would hide which configuration the machine last booted.

use crate::normalize::{parse_dword, split_command};
use crate::record::{AsepEntry, LocationKind};
use std::collections::BTreeMap;

/// Values accumulated for one `...\Services\<name>` key.
#[derive(Debug, Clone, Default)]
pub struct ServiceAccum {
    /// Service key name, as stored.
    pub name: String,
    /// The `...\Services\<name>` key path, as stored.
    pub key_path: String,
    /// `ControlSet001`, `CurrentControlSet`, ... when the path names one.
    pub control_set: Option<String>,
    /// Decoded `Start` value.
    pub start: Option<u32>,
    /// The rendered `Start` value, kept when it would not decode.
    pub start_raw: Option<String>,
    /// Decoded `Type` value.
    pub service_type: Option<u32>,
    /// The rendered `Type` value, kept when it would not decode.
    pub type_raw: Option<String>,
    /// `ImagePath`, as stored.
    pub image_path: Option<String>,
    /// `DisplayName`, as stored.
    pub display_name: Option<String>,
    /// `ObjectName` — the account the service runs as.
    pub object_name: Option<String>,
    /// `Parameters\ServiceDll` — the DLL a shared-process service loads.
    pub service_dll: Option<String>,
    /// `NetworkProvider\ProviderPath`, when the service registers one.
    pub network_provider_path: Option<String>,
}

/// Human label for a service `Start` value, or `None` when the value is not one
/// Windows defines.
pub fn start_type_label(start: u32) -> Option<&'static str> {
    match start {
        0 => Some("Boot"),
        1 => Some("System"),
        2 => Some("Automatic"),
        3 => Some("Manual"),
        4 => Some("Disabled"),
        _ => None,
    }
}

/// Human label for a service `Type` value.
///
/// Returns `None` for a base type Windows does not define, so an unrecognised
/// value is reported as unrecognised rather than folded into the nearest known
/// one.
pub fn service_type_label(service_type: u32) -> Option<String> {
    // winnt.h: SERVICE_INTERACTIVE_PROCESS is 0x100 and the
    // SERVICE_USERSERVICE_INSTANCE bit is 0x80, set on a per-user instance of a
    // 0x50/0x60 user-service template.
    let interactive = service_type & 0x100 != 0;
    let instance = service_type & 0x80 != 0;
    let base = service_type & !0x180u32;
    let name = match base {
        0x1 => "Kernel driver",
        0x2 => "File system driver",
        0x4 => "Adapter",
        0x8 => "Recognizer driver",
        0x10 => "Own-process service",
        0x20 => "Shared-process service (svchost)",
        0x30 => "Own- and shared-process service",
        0x40 => "User service",
        0x50 => "User own-process service",
        0x60 => "User shared-process service",
        _ => return None,
    };
    // The instance bit is defined only on a user-service template.
    if instance && !matches!(base, 0x50 | 0x60) {
        return None;
    }
    let mut label = name.to_string();
    if instance {
        label.push_str(" (per-user instance)");
    }
    if interactive {
        label.push_str(" (interactive)");
    }
    Some(label)
}

/// True when the start type causes the service or driver to load without a user
/// asking for it.
fn starts_by_itself(start: u32) -> bool {
    matches!(start, 0..=2)
}

/// The plain statement of what this service does and when.
fn runs_when(acc: &ServiceAccum, what: &str) -> String {
    let who = acc
        .object_name
        .as_deref()
        .map(|o| format!(" as {o}"))
        .unwrap_or_default();
    match acc.start {
        Some(0) => format!(
            "Loads during kernel initialisation, before the session manager starts: {what}."
        ),
        Some(1) => format!("Loads during kernel initialisation by the I/O subsystem: {what}."),
        Some(2) => format!("Starts automatically at boot, without any user action{who}: {what}."),
        Some(3) => format!(
            "Does not start on its own. Starts when something explicitly requests it{who}: {what}."
        ),
        Some(4) => format!("Disabled. Will not start until the start type is changed: {what}."),
        Some(other) => format!(
            "Start type {other} is not a value Windows defines, so when this would run \
             could not be determined: {what}."
        ),
        None => format!(
            "The start type could not be read, so when this would run could not be \
             determined: {what}."
        ),
    }
}

impl ServiceAccum {
    /// Which launcher an `ImagePath` belongs to, for the `full_path_required`
    /// statement (`HUNT-249` review). A `Type` of `0x1` (kernel driver), `0x2`
    /// (file system driver) or `0x8` (recognizer driver) is a driver, loaded
    /// by the kernel rather than the service control manager; so is a `Start` of `0` or `1` when `Type`
    /// is absent or unreadable, since Microsoft defines those start types for
    /// drivers only. A service `Type` (`0x10`–`0x60`) is a service. With neither, the
    /// launcher is not known and the statement names either.
    fn image_path_source(&self) -> crate::normalize::FullPathSource {
        use crate::normalize::FullPathSource;
        // Mask the interactive (0x100) and per-user-instance (0x80) bits;
        // SERVICE_ADAPTER (0x4) is documented only as reserved, so it names no
        // launcher and falls to the unknown-type arm.
        match self.service_type.map(|t| t & !0x180u32) {
            Some(0x1 | 0x2 | 0x8) => FullPathSource::DriverImagePath,
            Some(0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60) => FullPathSource::ServiceImagePath,
            _ if matches!(self.start, Some(0 | 1)) => FullPathSource::DriverImagePath,
            _ => FullPathSource::UnknownTypeImagePath,
        }
    }

    /// The rule for a bare `ImagePath`: observed for an own-process service,
    /// the documented full-path contract for everything else (only an
    /// own-process service was run on the observed build).
    fn image_path_rule(&self) -> crate::normalize::SearchRule {
        use crate::normalize::{FullPathSource, ObservedLauncher, SearchRule};
        let source = self.image_path_source();
        // Boot- and system-start entries are loaded by the kernel loader, which
        // was not run; only a service the SCM starts is covered.
        let own_process = self.service_type.map(|t| t & !0x180u32) == Some(0x10)
            && !matches!(self.start, Some(0 | 1));
        if source == FullPathSource::ServiceImagePath && own_process {
            SearchRule::Observed(ObservedLauncher::ServiceOwnProcess)
        } else {
            SearchRule::FullPathRequired(source)
        }
    }

    /// Turn the accumulated values into an entry.
    ///
    /// The image reported is `ServiceDll` when the service has one — for a
    /// shared-process service the `ImagePath` is `svchost.exe` and naming that
    /// as the thing that runs would point every examiner at the wrong file.
    /// `ImagePath` is retained alongside either way.
    pub fn into_entry(self) -> AsepEntry {
        let mut entry = AsepEntry::new(
            "service",
            if self.name.is_empty() {
                "(unnamed service key)".to_string()
            } else {
                self.name.clone()
            },
            self.key_path.clone(),
            LocationKind::RegistryKey,
        );

        let effective_image = self.service_dll.clone().or_else(|| self.image_path.clone());
        if let Some(cmd) = effective_image.as_deref() {
            entry.command = Some(cmd.to_string());
            if let Some(split) = split_command(cmd) {
                entry.image = Some(split.image);
                entry.arguments = split.arguments;
                entry.split_basis = Some(split.basis);
            }
        }
        // `CreateService` documents `ImagePath` as a fully qualified path
        // (`HUNT-249`); a `ServiceDll` is loaded by the service host and is not
        // covered by that contract, so it keeps the default rule.
        if self.service_dll.is_none() && self.image_path.is_some() {
            entry.search_context.rule = self.image_path_rule();
        }

        let what = match (self.service_dll.as_deref(), self.image_path.as_deref()) {
            (Some(dll), Some(host)) => format!("{host} loads {dll}"),
            (Some(dll), None) => format!("the service host loads {dll}"),
            (None, Some(img)) => format!("runs {img}"),
            (None, None) => "no image path is recorded for this service".to_string(),
        };
        entry.runs_when = runs_when(&self, &what);

        match self.start {
            Some(v) => {
                entry.enabled = Some(starts_by_itself(v));
                entry.enabled_basis = match start_type_label(v) {
                    Some(label) => format!("Start={v} ({label})"),
                    None => format!("Start={v} (not a start type Windows defines)"),
                };
                entry.put("service_start_type", serde_json::json!(v));
                entry.put(
                    "service_start_type_label",
                    serde_json::json!(start_type_label(v)),
                );
            }
            None => {
                entry.enabled = None;
                entry.enabled_basis = match self.start_raw.as_deref() {
                    Some(raw) => format!(
                        "The Start value could not be decoded (stored as '{raw}'), so \
                         whether this service starts on its own is unknown."
                    ),
                    None => "This service key has no Start value, so whether it starts on \
                             its own is unknown."
                        .to_string(),
                };
                entry.put("service_start_type", serde_json::Value::Null);
                entry.put("service_start_type_label", serde_json::Value::Null);
                entry.read_status = crate::record::ReadStatus::Unread(entry.enabled_basis.clone());
            }
        }

        entry.put("service_type", serde_json::json!(self.service_type));
        entry.put(
            "service_type_label",
            serde_json::json!(self.service_type.and_then(service_type_label)),
        );
        entry.put("service_image_path", serde_json::json!(self.image_path));
        entry.put("service_dll", serde_json::json!(self.service_dll));
        entry.put("service_display_name", serde_json::json!(self.display_name));
        entry.put("service_account", serde_json::json!(self.object_name));
        entry.put("control_set", serde_json::json!(self.control_set));
        entry.put("service_start_raw", serde_json::json!(self.start_raw));
        entry.put("service_type_raw", serde_json::json!(self.type_raw));

        if self.service_dll.is_some() {
            entry.observe(
                "service_loads_dll",
                "This service runs as a DLL inside a host process rather than as its own \
                 executable; the DLL is the code that runs.",
            );
        }
        if self.image_path.is_none() && self.service_dll.is_none() {
            entry.observe(
                "no_image_recorded",
                "The service key records neither an ImagePath nor a ServiceDll, so what \
                 it would execute is not stated in this hive.",
            );
        }

        entry.installed_time_unavailable_reason = Some(crate::KEY_TIME_UNAVAILABLE);
        entry
    }
}

/// Accumulator keyed by the lowercased `...\Services\<name>` key path.
pub type ServiceMap = BTreeMap<String, ServiceAccum>;

/// Fold one registry value into the service map.
///
/// `service_key_lower` is the lowercased `...\Services\<name>` prefix,
/// `subkey_tail` is whatever sits below it (`parameters`, `networkprovider`,
/// or nothing), and the remaining arguments are the value as stored.
#[allow(clippy::too_many_arguments)]
pub fn absorb_value(
    map: &mut ServiceMap,
    service_key_lower: &str,
    service_name: &str,
    service_key_path: &str,
    control_set: Option<&str>,
    subkey_tail: Option<&str>,
    value_name: &str,
    value_data: &str,
) {
    let acc = map
        .entry(service_key_lower.to_string())
        .or_insert_with(|| ServiceAccum {
            name: service_name.to_string(),
            key_path: service_key_path.to_string(),
            control_set: control_set.map(str::to_string),
            ..ServiceAccum::default()
        });

    let value = value_data.trim();
    match subkey_tail {
        None => match value_name.to_ascii_lowercase().as_str() {
            "start" => {
                acc.start = parse_dword(value);
                if acc.start.is_none() {
                    acc.start_raw = Some(value.to_string());
                }
            }
            "type" => {
                acc.service_type = parse_dword(value);
                if acc.service_type.is_none() {
                    acc.type_raw = Some(value.to_string());
                }
            }
            "imagepath" if !value.is_empty() => acc.image_path = Some(value.to_string()),
            "displayname" if !value.is_empty() => acc.display_name = Some(value.to_string()),
            "objectname" if !value.is_empty() => acc.object_name = Some(value.to_string()),
            _ => {}
        },
        Some(tail) => {
            if tail == "parameters"
                && value_name.eq_ignore_ascii_case("ServiceDll")
                && !value.is_empty()
            {
                acc.service_dll = Some(value.to_string());
            } else if tail == "networkprovider"
                && value_name.eq_ignore_ascii_case("ProviderPath")
                && !value.is_empty()
            {
                acc.network_provider_path = Some(value.to_string());
            }
        }
    }
}
