//! Which environment variable names the machine sets *persistently*.
//!
//! Every process's environment is mostly inherited: the machine-wide set under
//! `SYSTEM\…\Session Manager\Environment`, the user's own set under
//! `NTUSER.DAT\Environment`, and the per-logon set under `Volatile
//! Environment`. Those are the boring ones. A variable in a process's block
//! whose name appears in **none** of them was set at runtime — by
//! `SetEnvironmentVariable` in this process, or by whatever launched it — and
//! that is where `COR_PROFILER_PATH`, an overridden `APPDATA` and a
//! process-specific proxy live.
//!
//! # Why this fails closed rather than defaulting to "not persistent"
//!
//! The classification is a claim about a variable: *this one was deliberately
//! set*. It rests entirely on the persistent set being complete. If a hive was
//! not captured, or its `Environment` key's value list could not be walked, the
//! names it holds are missing from the set and every one of them would be
//! reported as deliberately set — which is an accusation, drawn from an absence
//! of evidence.
//!
//! So the set is either **established** or **unavailable**, and unavailable
//! makes [`PersistentVariables::classify`] return `None` for everything.
//! `None` and `Some(false)` are different columns, and a report must not
//! collapse them.

use std::collections::BTreeSet;

use seance_core::io::IncompleteReason;
use seance_memory::Incomplete;

use crate::environment::EnvironmentConfig;
use crate::profile::WindowsProfile;
use crate::registry::{list_hives, print_key_in_hive, RegistryError};

/// Ceiling on distinct persistent variable names collected.
///
/// A real machine has a few dozen. Reaching this means the value lists being
/// read are not value lists, and because a partial set produces *wrong*
/// classifications rather than missing ones, hitting it abandons the
/// classification entirely.
pub const MAX_PERSISTENT_NAMES: usize = 65_536;

/// The registry paths a persistent environment variable can be declared in.
///
/// Tried against every hive: a hive that does not have the key simply does not
/// contribute, and which hive a name came from is recorded so an examiner can
/// see whether the machine-wide set was actually read.
const PERSISTENT_KEYS: [&str; 4] = [
    // The machine-wide set. `CurrentControlSet` is a symbolic link that does
    // not exist as a key inside the hive itself, so the numbered control set is
    // tried as well and is normally the one that resolves.
    "CurrentControlSet\\Control\\Session Manager\\Environment",
    "ControlSet001\\Control\\Session Manager\\Environment",
    // The user's own set, and the set the logon session creates.
    "Environment",
    "Volatile Environment",
];

/// Variable names that are set explicitly often enough, on ordinary machines,
/// that their presence says nothing on its own.
///
/// A display hint and nothing more: it never affects
/// [`PersistentVariables::classify`], because "common" is a statement about
/// other machines and "persistent" is a statement about *this* one.
const COMMONLY_INHERITED: [&str; 45] = [
    "ProgramFiles",
    "CommonProgramFiles",
    "SystemDrive",
    "SystemRoot",
    "ProgramData",
    "PUBLIC",
    "ALLUSERSPROFILE",
    "COMPUTERNAME",
    "SESSIONNAME",
    "USERNAME",
    "USERPROFILE",
    "PROMPT",
    "USERDOMAIN",
    "AppData",
    "CommonFiles",
    "CommonDesktop",
    "CommonProgramGroups",
    "CommonStartMenu",
    "CommonStartUp",
    "Cookies",
    "DesktopDirectory",
    "Favorites",
    "History",
    "NetHood",
    "PersonalDocuments",
    "RecycleBin",
    "StartMenu",
    "Templates",
    "AltStartup",
    "CommonFavorites",
    "ConnectionWizard",
    "DocAndSettingRoot",
    "InternetCache",
    "windir",
    "Path",
    "HOMEDRIVE",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "ProgramFiles(x86)",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "PSModulePath",
    "PROCESSOR_IDENTIFIER",
    "FP_NO_HOST_CHECK",
    "LOCALAPPDATA",
];

/// Whether a variable name is one an ordinary machine sets on nearly every
/// process.
///
/// For suppressing noise in a rendered table. Never a substitute for
/// [`PersistentVariables::classify`]: an attacker who calls their variable
/// `Path` gets no protection from this, because the classification that matters
/// comes from the registry of the machine in evidence.
pub fn is_commonly_inherited(name: &str) -> bool {
    COMMONLY_INHERITED
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// One registry key that contributed names to the persistent set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentSource {
    /// Address of the `_CMHIVE` the key came from.
    pub hive: u64,
    /// The path as it resolved inside that hive.
    pub path: String,
    /// How many value names it contributed.
    pub names: usize,
}

impl PersistentSource {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"hive": self.hive, "path": self.path, "names": self.names})
    }
}

/// Whether the persistent set was established, and if not, why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistentState {
    /// Every key that exists was read in full, so a name's absence from the set
    /// means it really is not set persistently.
    Established,
    /// The caller asked for no classification.
    NotRequested,
    /// The set could not be established. The string says what went wrong, and
    /// every classification is `None` as a result.
    Unavailable(String),
}

impl PersistentState {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            PersistentState::Established => "established",
            PersistentState::NotRequested => "not_requested",
            PersistentState::Unavailable(_) => "unavailable",
        }
    }
}

/// The names of every variable this machine sets persistently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentVariables {
    /// Names, lower-cased, because Windows matches environment variable names
    /// without regard to case.
    names: BTreeSet<String>,
    /// The keys that contributed, so an examiner can see whether the
    /// machine-wide set was among them.
    pub sources: Vec<PersistentSource>,
    /// Whether the set is usable.
    pub state: PersistentState,
    /// Everything odd that did not stop the set being established.
    pub notes: Vec<String>,
}

impl PersistentVariables {
    /// A set nobody asked for.
    pub fn not_requested() -> Self {
        Self {
            names: BTreeSet::new(),
            sources: Vec::new(),
            state: PersistentState::NotRequested,
            notes: Vec::new(),
        }
    }

    /// A set that could not be established, and why.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            names: BTreeSet::new(),
            sources: Vec::new(),
            state: PersistentState::Unavailable(detail.into()),
            notes: Vec::new(),
        }
    }

    /// Read every hive's environment keys and collect the names they declare.
    ///
    /// Never fails: a hive list that will not walk, a key whose values could not
    /// be enumerated and a value list that was truncated all produce an
    /// [`PersistentState::Unavailable`] set, which classifies nothing rather
    /// than classifying wrongly.
    pub fn from_profile(profile: &WindowsProfile, config: &EnvironmentConfig) -> Self {
        let listing = match list_hives(profile) {
            Ok(listing) => listing,
            Err(err) => {
                return Self::unavailable(format!(
                    "the registry hive list could not be walked, so which variables are set \
                     persistently is unknown: {err}"
                ))
            }
        };

        let mut out = Self {
            names: BTreeSet::new(),
            sources: Vec::new(),
            state: PersistentState::Established,
            notes: Vec::new(),
        };
        let cap = config.max_persistent_names.max(1);

        if !listing.is_complete() {
            // A hive that was not reached may be the one holding the user's own
            // Environment key, and its absence would make every name in it look
            // deliberately set.
            return Self::unavailable(format!(
                "the registry hive list was not walked end to end, so a hive holding environment \
                 variables may have been missed: {}",
                listing
                    .incomplete
                    .iter()
                    .map(|entry| entry.detail.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }

        for hive in &listing.hives {
            for path in PERSISTENT_KEYS {
                match print_key_in_hive(profile, hive.address, Some(path)) {
                    Ok(key) => {
                        if !key.values.is_complete() {
                            return Self::unavailable(format!(
                                "the values of '{path}' in the hive at {:#x} could not be \
                                 enumerated in full, so a name set there would look deliberately \
                                 set in every process",
                                hive.address
                            ));
                        }
                        let mut added = 0usize;
                        for value in &key.values.values {
                            if value.name.text.is_empty() {
                                continue;
                            }
                            if out.names.len() >= cap {
                                return Self::unavailable(format!(
                                    "more than {cap} persistent variable names were found, which \
                                     is past anything a real machine declares, so the set was not \
                                     trusted"
                                ));
                            }
                            if out.names.insert(value.name.text.to_lowercase()) {
                                added = added.saturating_add(1);
                            }
                            if !value.name.well_formed {
                                out.notes.push(format!(
                                    "a value name under '{path}' in the hive at {:#x} is not \
                                     valid UTF-16, so it may not match the name a process holds",
                                    hive.address
                                ));
                            }
                        }
                        out.sources.push(PersistentSource {
                            hive: hive.address,
                            path: path.to_string(),
                            names: added,
                        });
                    }
                    // A hive that simply does not have the key contributes
                    // nothing, and that is ordinary: SYSTEM has no `Environment`
                    // at its root and NTUSER.DAT has no control set. It only
                    // counts as ordinary when the search that failed was itself
                    // complete.
                    Err(RegistryError::KeyNotFound { certainty, .. })
                        if certainty.contains("read in full") => {}
                    Err(err) => {
                        return Self::unavailable(format!(
                            "'{path}' in the hive at {:#x} could not be resolved, so the \
                             persistent set may be short: {err}",
                            hive.address
                        ))
                    }
                }
            }
        }

        if out.sources.is_empty() {
            return Self::unavailable(
                "no hive in this image declares an environment key, so there is nothing to \
                 compare a process's variables against"
                    .to_string(),
            );
        }
        out
    }

    /// Whether a variable of this name is set persistently on this machine.
    ///
    /// `None` when the set could not be established. A caller must render that
    /// as *unknown*: reporting it as `false` claims the variable was set
    /// deliberately, which is the finding, drawn from no evidence at all.
    pub fn classify(&self, name: &str) -> Option<bool> {
        match self.state {
            PersistentState::Established => Some(self.names.contains(&name.to_lowercase())),
            _ => None,
        }
    }

    /// How many distinct names the set holds.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the set holds no names.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The names, lower-cased, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }

    /// Whether the classification is usable.
    pub fn is_complete(&self) -> bool {
        self.state == PersistentState::Established
    }

    /// Everything a report must declare about this set.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        match &self.state {
            PersistentState::Established => Vec::new(),
            PersistentState::NotRequested => vec![Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "the persistent environment variables were not read, so no variable can be shown \
                 as having been set deliberately"
                    .to_string(),
            )],
            PersistentState::Unavailable(detail) => vec![Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "which variables are set persistently could not be established, so no \
                     variable is shown as having been set deliberately: {detail}"
                ),
            )],
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "state": self.state.as_str(),
            "detail": match &self.state {
                PersistentState::Unavailable(detail) => Some(detail.clone()),
                _ => None,
            },
            "name_count": self.names.len(),
            "names": self.names.iter().collect::<Vec<_>>(),
            "sources": self.sources.iter().map(PersistentSource::to_json).collect::<Vec<_>>(),
            "notes": self.notes,
            "complete": self.is_complete(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A set that was never read must not classify anything, because the only
    /// answer it could give is the accusatory one.
    #[test]
    fn a_set_that_was_not_requested_classifies_nothing() {
        let set = PersistentVariables::not_requested();
        assert_eq!(set.classify("PATH"), None);
        assert_eq!(set.classify("COR_PROFILER_PATH"), None);
        assert!(!set.is_complete());
        assert_eq!(set.incomplete().len(), 1);
    }

    /// The same for a set that was attempted and failed: the reason travels
    /// with it.
    #[test]
    fn an_unavailable_set_carries_the_reason_it_could_not_be_established() {
        let set = PersistentVariables::unavailable("the SYSTEM hive was not captured");
        assert_eq!(set.classify("PATH"), None);
        assert!(!set.is_complete());
        assert!(set.incomplete()[0]
            .detail
            .contains("the SYSTEM hive was not captured"));
        assert_eq!(set.to_json()["state"], serde_json::json!("unavailable"),);
    }

    /// An established set answers both ways, and matching ignores case exactly
    /// as Windows does.
    #[test]
    fn an_established_set_answers_both_ways_and_ignores_case() {
        let mut set = PersistentVariables::not_requested();
        set.state = PersistentState::Established;
        set.names.insert("path".into());
        set.names.insert("windir".into());
        assert_eq!(set.classify("PATH"), Some(true));
        assert_eq!(set.classify("Path"), Some(true));
        assert_eq!(set.classify("COR_PROFILER_PATH"), Some(false));
        assert!(set.is_complete());
        assert!(set.incomplete().is_empty());
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    /// The "common" list is a rendering hint, and it must not be mistaken for
    /// the classification: a name can be common and still not persistent here.
    #[test]
    fn the_common_list_is_case_insensitive_and_separate_from_the_classification() {
        assert!(is_commonly_inherited("PATH"));
        assert!(is_commonly_inherited("path"));
        assert!(is_commonly_inherited("SystemRoot"));
        assert!(!is_commonly_inherited("COR_PROFILER_PATH"));
        assert!(!is_commonly_inherited("HTTPS_PROXY"));

        // Common says nothing about this machine.
        let set = PersistentVariables::not_requested();
        assert_eq!(set.classify("PATH"), None);
    }

    /// Every persistent key upstream reads is tried, including the numbered
    /// control set that is the one that actually resolves inside a SYSTEM hive.
    #[test]
    fn the_numbered_control_set_is_tried_because_currentcontrolset_is_a_link() {
        assert!(PERSISTENT_KEYS
            .iter()
            .any(|path| path.starts_with("ControlSet001\\")));
        assert!(PERSISTENT_KEYS.contains(&"Volatile Environment"));
        assert!(PERSISTENT_KEYS.contains(&"Environment"));
    }
}
