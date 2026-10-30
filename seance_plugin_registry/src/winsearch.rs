//! Windows Search: was the machine indexing, and where is the index.
//!
//! `ROADMAP` §2.6, question 42 of the NIST CFReDS Data Leakage key. Whether
//! indexing was on decides whether `Windows.edb` is worth looking for — and
//! `Windows.edb` holds file names and content excerpts for files that have
//! since been deleted.
//!
//! # Two keys, in two hives, and both are needed
//!
//! `SYSTEM\ControlSet00N\Services\WSearch` says whether the **service** was
//! configured to run: `Start` is the standard service start type, and
//! `DelayedAutoStart` distinguishes "automatic" from "automatic (delayed
//! start)". Measured on the real Windows 7 hive: `Start = 2`,
//! `DelayedAutoStart = 1`, in **both** control sets.
//!
//! `SOFTWARE\Microsoft\Windows Search` says whether setup completed and where
//! the index lives.
//!
//! # What this will not say
//!
//! **The service being configured to start is not the index being populated.**
//! A service set to automatic on a machine that was imaged minutes after
//! installation has indexed nothing. So the record reports the configuration
//! and says, in words, that whether the index holds anything is a question for
//! `Windows.edb` itself.

use serde_json::{json, Value};

/// The standard service start types.
///
/// Named from the `SERVICE_*_START` constants. A value outside the set is
/// reported as the number it is.
pub fn start_type_label(start: u32) -> Option<&'static str> {
    match start {
        0 => Some("boot"),
        1 => Some("system"),
        2 => Some("automatic"),
        3 => Some("manual"),
        4 => Some("disabled"),
        _ => None,
    }
}

/// What the two keys say.
#[derive(Clone, Debug, Default)]
pub struct WindowsSearchState {
    pub control_set: Option<String>,
    /// `Start`, raw.
    pub start_raw: Option<u32>,
    /// `DelayedAutoStart`.
    pub delayed_auto_start: Option<bool>,
    pub image_path: Option<String>,
    pub runs_as: Option<String>,
    /// `SetupCompletedSuccessfully` from the `SOFTWARE` side.
    pub setup_completed: Option<bool>,
    /// `DataDirectory` — where `Windows.edb` lives.
    pub data_directory: Option<String>,
    pub key_path: String,
    pub key_last_written: Option<String>,
    /// Whether the `Services\WSearch` key was there at all.
    ///
    /// `false` is a measured absence, not a failure to look, and it is the
    /// commonest case on Windows XP -- see the module comment.
    pub service_key_present: bool,
}

impl WindowsSearchState {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("WindowsSearchState"));
        m.insert("name".into(), json!("Windows Search"));
        m.insert("control_set".into(), json!(self.control_set));
        m.insert(
            "service_key_present".into(),
            json!(self.service_key_present),
        );
        if !self.service_key_present && self.control_set.is_some() {
            // The absence, said in words. Without it a screen with no Windows
            // Search section reads as "indexing was off" rather than as "this
            // build of Windows kept no key of that name".
            m.insert(
                "service_key_absent_note".into(),
                json!(
                    "This control set was read and holds no WSearch service key. That is an \
                     absence in the evidence, not a gap in this build's reach: Windows XP's \
                     indexer was a different service (`cisvc`), and a machine with no \
                     WSearch key never had the Windows Search service to configure. Whether \
                     some other indexer ran is a question this record does not answer."
                ),
            );
        }
        m.insert("start_raw".into(), json!(self.start_raw));
        match self.start_raw.and_then(start_type_label) {
            Some(label) => {
                m.insert("start_type".into(), json!(label));
                // "Automatic" and "automatic (delayed)" are different
                // configurations and Windows shows them differently.
                let effective = match (label, self.delayed_auto_start) {
                    ("automatic", Some(true)) => "automatic (delayed start)".to_string(),
                    _ => label.to_string(),
                };
                m.insert("start_type_effective".into(), json!(effective));
                m.insert(
                    "indexing_configured_to_run".into(),
                    json!(matches!(label, "boot" | "system" | "automatic")),
                );
            }
            None => {
                if let Some(raw) = self.start_raw {
                    m.insert(
                        "start_type_note".into(),
                        json!(format!(
                            "The service's Start value is {raw}, which is not one of the five \
                             start types this build names. It is reported as the number it is \
                             and no start type is claimed for it."
                        )),
                    );
                }
            }
        }
        m.insert("delayed_auto_start".into(), json!(self.delayed_auto_start));
        m.insert("image_path".into(), json!(self.image_path));
        m.insert("runs_as".into(), json!(self.runs_as));
        m.insert("setup_completed".into(), json!(self.setup_completed));
        m.insert("data_directory".into(), json!(self.data_directory));
        if self.data_directory.is_some() {
            m.insert(
                "index_file_note".into(),
                json!(
                    "Windows.edb lives under this directory. It holds file names and \
                       content excerpts, including for files that have since been deleted, \
                       and is worth looking for when indexing was configured to run."
                ),
            );
        }
        // The distinction that matters.
        m.insert("index_populated".into(), json!(false));
        m.insert(
            "index_populated_basis".into(),
            json!(
                "This record is the service's CONFIGURATION. A service set to start \
                   automatically on a machine imaged shortly after installation has indexed \
                   nothing. Whether the index holds anything is a question for Windows.edb \
                   itself, which this record does not read."
            ),
        );
        m.insert("key_path".into(), json!(self.key_path));
        m.insert("key_last_written".into(), json!(self.key_last_written));
        Value::Object(m)
    }
}

/// Recognise the service key, returning its control set.
pub fn wsearch_service_key(key_path: &str) -> Option<String> {
    let segments: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
    let lower: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();
    let last = lower.last()?;
    if last != "wsearch" {
        return None;
    }
    if lower.get(lower.len().checked_sub(2)?)? != "services" {
        return None;
    }
    let cs = segments.get(lower.len().checked_sub(3)?)?;
    let l = cs.to_ascii_lowercase();
    (l.starts_with("controlset") || l == "currentcontrolset").then(|| cs.to_string())
}

/// Recognise the `SOFTWARE\Microsoft\Windows Search` key.
pub fn wsearch_software_key(key_path: &str) -> bool {
    let segments: Vec<String> = key_path
        .split('\\')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    segments.last().is_some_and(|s| s == "windows search")
        && segments
            .get(segments.len().wrapping_sub(2))
            .is_some_and(|s| s == "microsoft")
}

/// Turn the walk's capture into records.
///
/// `control_sets_in_hive` is every control set the walk saw, so the absence of
/// the key can be stated per control set rather than inferred from silence.
pub fn emit(
    capture: &crate::resident::ResidentCapture,
    control_sets_in_hive: &[String],
) -> Vec<Value> {
    use crate::resident::Anchor;

    // The SOFTWARE side, if this hive is SOFTWARE. There is one such key, and
    // its values are folded into every service record so a reader does not have
    // to join two records by hand.
    let mut setup_completed = None;
    let mut data_directory = None;
    for key in capture.keys_matching(|a| matches!(a, Anchor::WindowsSearchSoftware)) {
        for v in &key.values {
            if v.name.eq_ignore_ascii_case("SetupCompletedSuccessfully") {
                setup_completed = v
                    .data
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .map(u32::from_le_bytes)
                    .map(|n| n != 0);
            }
            if v.name.eq_ignore_ascii_case("DataDirectory") {
                data_directory = Some(utf16le(&v.data)).filter(|s| !s.is_empty());
            }
        }
    }

    let mut out = Vec::new();
    let mut sets_with_the_key: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::WindowsSearchService { .. })) {
        let Anchor::WindowsSearchService { control_set } = &key.anchor else {
            continue;
        };
        let dword = |name: &str| {
            key.values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(name))
                .and_then(|v| v.data.get(..4))
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
        };
        let sz = |name: &str| {
            key.values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(name))
                .map(|v| utf16le(&v.data))
                .filter(|s| !s.is_empty())
        };
        sets_with_the_key.insert(control_set.clone());
        out.push(
            WindowsSearchState {
                control_set: Some(control_set.clone()),
                service_key_present: true,
                start_raw: dword("Start"),
                delayed_auto_start: dword("DelayedAutoStart").map(|v| v != 0),
                image_path: sz("ImagePath"),
                runs_as: sz("ObjectName"),
                setup_completed,
                data_directory: data_directory.clone(),
                key_path: key.key_path.clone(),
                key_last_written: seance_core::time::filetime_to_rfc3339(key.last_written_filetime),
            }
            .to_json(),
        );
    }
    // The absence that silence would hide: a control set the walk read which
    // holds no `WSearch` key. One record per control set, because each is a
    // separate place the answer could have been -- the same discipline BAM's
    // coverage records use for a hive that predates its key.
    for control_set in control_sets_in_hive {
        if sets_with_the_key.contains(control_set) {
            continue;
        }
        out.push(
            WindowsSearchState {
                control_set: Some(control_set.clone()),
                service_key_present: false,
                setup_completed,
                data_directory: data_directory.clone(),
                key_path: format!("{control_set}\\Services\\WSearch"),
                ..Default::default()
            }
            .to_json(),
        );
    }

    // A SOFTWARE hive has the setup state and no service key. Emit it alone
    // rather than dropping it: "setup completed" is an answer.
    if out.is_empty() && (setup_completed.is_some() || data_directory.is_some()) {
        out.push(
            WindowsSearchState {
                setup_completed,
                data_directory,
                key_path: "(SOFTWARE\\Microsoft\\Windows Search)".into(),
                ..Default::default()
            }
            .to_json(),
        );
    }
    out
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}
