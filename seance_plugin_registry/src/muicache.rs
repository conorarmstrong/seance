//! MUICache: the display names the shell cached, and what that does not mean.
//!
//! # What it is
//!
//! The shell caches an application's friendly name and company so Explorer
//! need not reload them from the binary's resources. Two forms:
//! `Software\Microsoft\Windows\ShellNoRoam\MUICache` in `NTUSER.DAT` (XP), and
//! `Local Settings\Software\Microsoft\Windows\Shell\MuiCache` in
//! `UsrClass.dat` (Windows 7+). Note the casing difference, which is real.
//!
//! `ROADMAP` §2.5.
//!
//! # What it is not
//!
//! **It is not evidence of execution**, and over-claiming it as such is the
//! standard error with this artifact. What its presence establishes is that the
//! shell displayed that application's name — which most often follows from
//! running it, and is also written by a properties dialog, a context menu, and
//! a shell-extension enumeration. Every record carries
//! `execution_evidence: false` and the basis in words.
//!
//! # And it carries no per-entry time
//!
//! The key's `nk` last-write time is the only date here, and it belongs to the
//! **key**. Stamping it on each entry without saying whose it is would date all
//! 131 entries of a real XP `MUICache` to the most recent one. So it is
//! reported once, scoped, and **no timeline event is emitted at all**.

use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Which of the two key forms an entry came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceForm {
    /// `…\ShellNoRoam\MUICache` — `NTUSER.DAT`, Windows XP.
    ShellNoRoam,
    /// `…\Shell\MuiCache` — `UsrClass.dat`, Windows 7+.
    UsrClassShell,
}

impl SourceForm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ShellNoRoam => "shellnoroam",
            Self::UsrClassShell => "usrclass_shell",
        }
    }
}

/// Recognise a MUICache key from its path.
pub fn muicache_key(key_path: &str) -> Option<SourceForm> {
    let segments: Vec<String> = key_path
        .split('\\')
        .filter(|s| !s.is_empty())
        .skip(1) // the walk's synthetic root
        .map(|s| s.to_ascii_lowercase())
        .collect();
    // The key itself, never a subkey of it: `BagMRU` and friends live under
    // neighbouring paths and must not be swept in.
    let last = segments.last()?;
    if last != "muicache" {
        return None;
    }
    let parent = segments.get(segments.len().checked_sub(2)?)?;
    match parent.as_str() {
        "shellnoroam" => Some(SourceForm::ShellNoRoam),
        "shell" => Some(SourceForm::UsrClassShell),
        _ => None,
    }
}

/// Whether a value on a MUICache key names an application.
///
/// `LangID` is in both forms, is two bytes of `REG_BINARY`, and is not an
/// application. It sits on every machine, so a builder taking every value as a
/// program would publish it as an installed application everywhere — the third
/// instance of `HUNT-122`'s shape in this one roadmap item.
pub fn is_application_value(name: &str) -> bool {
    !name.eq_ignore_ascii_case("LangID")
}

/// What the value name refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuiTargetKind {
    /// A drive-lettered application path.
    DosPath,
    /// A localised-resource reference, `@<dll>,-<id>`.
    ///
    /// **Not a file path.** `@shell32.dll,-22075` names a string inside a DLL,
    /// and reporting it as a program on the machine would be a fabricated
    /// finding — an examiner correlating it against the filesystem would find
    /// nothing and read the absence as a deletion.
    ResourceReference,
    /// A name of some other shape, reported as stored.
    Unclassified,
}

impl MuiTargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DosPath => "dos_path",
            Self::ResourceReference => "resource_reference",
            Self::Unclassified => "unclassified",
        }
    }
}

/// The basis sentence every record carries.
const BASIS: &str =
    "the shell cached this application's display name; that is not by itself a record of \
     execution — a properties dialog, a context menu and a shell-extension enumeration all \
     write here too";

/// One application's cached display name.
#[derive(Clone, Debug)]
pub struct MuiCacheEntry {
    pub source_form: SourceForm,
    pub application_path: Option<String>,
    pub friendly_name: Option<String>,
    pub company: Option<String>,
    pub resource_dll: Option<String>,
    pub resource_id: Option<i64>,
    pub target_kind: MuiTargetKind,
    /// Every raw value name that fed this record, so the pairing can be checked
    /// against the hive.
    pub value_names: Vec<String>,
    pub key_path: Option<String>,
    pub key_last_written: Option<String>,
}

/// The two suffixes the Windows 7+ form uses.
const FRIENDLY_SUFFIX: &str = ".friendlyappname";
const COMPANY_SUFFIX: &str = ".applicationcompany";

/// Split a Windows 7+ value name into its path and which field it carries.
fn split_suffix(name: &str) -> (String, Option<&'static str>) {
    let lower = name.to_ascii_lowercase();
    if let Some(stem) = lower.strip_suffix(FRIENDLY_SUFFIX) {
        return (name[..stem.len()].to_string(), Some("friendly"));
    }
    if let Some(stem) = lower.strip_suffix(COMPANY_SUFFIX) {
        return (name[..stem.len()].to_string(), Some("company"));
    }
    (name.to_string(), None)
}

/// Classify a name, and pull a resource reference apart.
fn classify(name: &str) -> (MuiTargetKind, Option<String>, Option<String>, Option<i64>) {
    if let Some(rest) = name.strip_prefix('@') {
        // `@<dll>,-<id>`. Split on the LAST comma, because a path may contain
        // none but never more after the id.
        if let Some((dll, id)) = rest.rsplit_once(',') {
            if let Ok(parsed) = id.trim().parse::<i64>() {
                return (
                    MuiTargetKind::ResourceReference,
                    None,
                    Some(dll.to_string()),
                    Some(parsed),
                );
            }
        }
        return (
            MuiTargetKind::ResourceReference,
            None,
            Some(rest.to_string()),
            None,
        );
    }
    let b = name.as_bytes();
    let drive_lettered = b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.get(1) == Some(&b':')
        && matches!(b.get(2), Some(b'\\') | Some(b'/'));
    if drive_lettered {
        (MuiTargetKind::DosPath, Some(name.to_string()), None, None)
    } else {
        (
            MuiTargetKind::Unclassified,
            Some(name.to_string()),
            None,
            None,
        )
    }
}

/// Pair the values on a MUICache key into one record per application.
///
/// The Windows 7+ form writes two values per application — `.FriendlyAppName`
/// and `.ApplicationCompany` — and emitting them separately would double the
/// application count and leave two half-records where the hive holds one fact.
pub fn pair_values(source_form: SourceForm, values: &[(String, String)]) -> Vec<MuiCacheEntry> {
    let mut by_target: BTreeMap<String, MuiCacheEntry> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();

    for (name, data) in values {
        if !is_application_value(name) {
            continue;
        }
        let (stem, field) = split_suffix(name);
        let (target_kind, application_path, resource_dll, resource_id) = classify(&stem);
        let entry = by_target.entry(stem.clone()).or_insert_with(|| {
            order.push(stem.clone());
            MuiCacheEntry {
                source_form,
                application_path,
                friendly_name: None,
                company: None,
                resource_dll,
                resource_id,
                target_kind,
                value_names: Vec::new(),
                key_path: None,
                key_last_written: None,
            }
        });
        entry.value_names.push(name.clone());
        match field {
            Some("friendly") => entry.friendly_name = Some(data.clone()),
            Some("company") => entry.company = Some(data.clone()),
            // The XP form has no suffix: the data IS the friendly name.
            None if source_form == SourceForm::ShellNoRoam => {
                entry.friendly_name = Some(data.clone())
            }
            // A Windows 7+ suffix this build does not recognise claims no
            // field, and the raw name above is the record of it.
            _ => {}
        }
    }
    order
        .into_iter()
        .filter_map(|k| by_target.remove(&k))
        .collect()
}

impl MuiCacheEntry {
    pub fn to_json(&self) -> Value {
        let name = self
            .friendly_name
            .clone()
            .or_else(|| self.application_path.clone())
            .or_else(|| self.value_names.first().cloned())
            .unwrap_or_else(|| "(unnamed)".to_string());
        json!({
            "type": "MuiCacheEntry",
            "name": name,
            "source_form": self.source_form.as_str(),
            "application_path": self.application_path,
            "friendly_name": self.friendly_name,
            "company": self.company,
            "resource_dll": self.resource_dll,
            "resource_id": self.resource_id,
            "target_kind": self.target_kind.as_str(),
            "value_names": self.value_names,
            "key_path": self.key_path,
            "key_last_written": self.key_last_written,
            // Whose time that is. Without this, every entry on a 131-value key
            // would read as dated to the most recent write.
            "key_last_written_scope": "the MUICache key, not this entry",
            "execution_evidence": false,
            "basis": BASIS,
        })
    }
}

/// What was found on one MUICache key.
#[derive(Clone, Debug)]
pub struct MuiCacheCoverage {
    pub source_form: SourceForm,
    pub key_path: String,
    pub values_total: usize,
    pub applications: usize,
    pub bookkeeping_values: usize,
}

impl MuiCacheCoverage {
    pub fn to_json(&self) -> Value {
        json!({
            "type": "MuiCacheCoverage",
            "name": format!("MUICache ({})", self.source_form.as_str()),
            "source_form": self.source_form.as_str(),
            "key_path": self.key_path,
            "values_total": self.values_total,
            "applications": self.applications,
            "bookkeeping_values": self.bookkeeping_values,
            "coverage_note": if self.values_total == 0 {
                "This MUICache key exists and holds no values: the shell cached no display \
                 names for this user. That is not the same as this build not having looked."
                    .to_string()
            } else {
                format!(
                    "{} application(s) from {} value(s) on the key; {} excluded as the \
                     shell's own bookkeeping (LangID).",
                    self.applications, self.values_total, self.bookkeeping_values
                )
            },
            "execution_evidence": false,
            "basis": BASIS,
        })
    }
}

/// Turn the walk's capture into records.
pub fn emit(capture: &crate::resident::ResidentCapture) -> Vec<Value> {
    use crate::resident::Anchor;

    let mut out = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::MuiCache { .. })) {
        let Anchor::MuiCache { form } = &key.anchor else {
            continue;
        };
        // The stored strings are UTF-16LE; the walk captured the raw bytes.
        let values: Vec<(String, String)> = key
            .values
            .iter()
            .map(|v| {
                (
                    v.name.clone(),
                    seance_core::codepage::decode_utf16le(&v.data),
                )
            })
            .collect();
        let bookkeeping = values
            .iter()
            .filter(|(n, _)| !is_application_value(n))
            .count();
        let mut entries = pair_values(*form, &values);
        let key_last_written = seance_core::time::filetime_to_rfc3339(key.last_written_filetime);
        for e in &mut entries {
            e.key_path = Some(key.key_path.clone());
            e.key_last_written = key_last_written.clone();
        }
        out.push(
            MuiCacheCoverage {
                source_form: *form,
                key_path: key.key_path.clone(),
                values_total: values.len(),
                applications: entries.len(),
                bookkeeping_values: bookkeeping,
            }
            .to_json(),
        );
        out.extend(entries.iter().map(MuiCacheEntry::to_json));
    }
    out
}
