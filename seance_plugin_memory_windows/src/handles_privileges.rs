//! Token privileges: what a process was permitted to do, whether or not it did.
//!
//! A Windows privilege is a right that is not tied to any object — `SeDebug`
//! lets a process open *any* other process's memory, `SeLoadDriver` lets it put
//! code in the kernel, `SeTakeOwnership` lets it seize any file on the volume
//! regardless of its ACL. Which of them a process holds is the difference
//! between "this program could have read the victim's browser memory" and "it
//! could not have". That is a question a report gets asked in court, and the
//! answer is three bits per privilege in one structure.
//!
//! # Present, enabled and enabled-by-default are three different claims
//!
//! * **Present** — the privilege is in the token at all. A token that does not
//!   have `SeDebugPrivilege` present can never acquire it.
//! * **Enabled** — the privilege is active *right now*. A process must enable a
//!   present privilege before the kernel honours it, which most programs do for
//!   the moment they need it and then drop.
//! * **Enabled by default** — the privilege comes up enabled every time the
//!   token is used, which is how a service account ends up permanently able to
//!   do something.
//!
//! Collapsing the three into one "has privilege" column loses the distinction
//! between a process that *could* have escalated and one that *was configured
//! to*. All three are carried per privilege here.
//!
//! # Two completely different storage shapes
//!
//! | Build | Where privileges live |
//! |---|---|
//! | XP, 2003 | `_TOKEN.Privileges` is a **pointer** to an array of `_LUID_AND_ATTRIBUTES`, `_TOKEN.PrivilegeCount` long |
//! | Vista and later | `_TOKEN.Privileges` is a `_SEP_TOKEN_PRIVILEGES`: three 64-bit **bitmaps**, one bit per privilege value |
//!
//! The two produce different row sets and this module does not pretend
//! otherwise. On the bitmap builds every one of the 64 bit positions is
//! examined, so a privilege that is *absent* is still reported, with `present`
//! false — the absence of `SeDebugPrivilege` from a token is itself evidence.
//! On the array builds only the privileges actually in the array exist, and
//! every one of them is present by construction; there is no way to ask the
//! structure about a privilege it does not list, and inventing rows saying
//! "absent" would be asserting something the evidence does not contain.
//! [`PrivilegeShape`] travels with the result so a reader knows which of the two
//! they are looking at.
//!
//! # A bit position with no name is not a privilege
//!
//! The 64 bits are sparsely assigned: values 0 and 1 are unused, and the
//! highest privilege any shipping Windows defines is 36. A set bit outside
//! [`PRIVILEGES`] is reported with `name` as `None` rather than dropped or
//! given a made-up label, because a token with bit 47 set is either a build
//! newer than this table or a structure read at the wrong offset, and both are
//! worth seeing.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::required_size;
use seance_memory::object::StructReader;
use seance_memory::Incomplete;

use crate::handles::token::{first_member, ProcessToken, TokenError, TokenSymbols, TYPE_TOKEN};
use crate::module::STAGE_HANDLES;
use crate::profile::WindowsProfile;

/// The Vista-and-later structure holding the three privilege bitmaps.
pub const TYPE_SEP_TOKEN_PRIVILEGES: &str = "_SEP_TOKEN_PRIVILEGES";

/// The XP-and-2003 array element: one privilege and its attribute flags.
pub const TYPE_LUID_AND_ATTRIBUTES: &str = "_LUID_AND_ATTRIBUTES";

/// How many bit positions a `_SEP_TOKEN_PRIVILEGES` bitmap has.
pub const PRIVILEGE_BITS: u64 = 64;

/// `SE_PRIVILEGE_ENABLED_BY_DEFAULT`, in `_LUID_AND_ATTRIBUTES.Attributes`.
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u64 = 0x1;

/// `SE_PRIVILEGE_ENABLED`, in `_LUID_AND_ATTRIBUTES.Attributes`.
pub const SE_PRIVILEGE_ENABLED: u64 = 0x2;

/// Ceiling on entries read from an XP-shaped privilege array.
///
/// A token has at most a few dozen privileges; the count came out of the image,
/// so a token claiming more than this is refused rather than iterated.
pub const MAX_PRIVILEGE_ARRAY: u64 = 1024;

/// Every privilege Windows defines, by the value stored in the token.
///
/// The value is not an offset into any structure — it is the `LUID` low part
/// that `LookupPrivilegeValue` returns, and it is fixed by the API rather than
/// by a build — so it is a table here rather than something read from the
/// image. Each entry is `(value, constant name, what it permits)`.
pub const PRIVILEGES: [(u64, &str, &str); 35] = [
    (2, "SeCreateTokenPrivilege", "Create a token object"),
    (
        3,
        "SeAssignPrimaryTokenPrivilege",
        "Replace a process-level token",
    ),
    (4, "SeLockMemoryPrivilege", "Lock pages in memory"),
    (5, "SeIncreaseQuotaPrivilege", "Increase quotas"),
    (
        6,
        "SeMachineAccountPrivilege",
        "Add workstations to the domain",
    ),
    (7, "SeTcbPrivilege", "Act as part of the operating system"),
    (8, "SeSecurityPrivilege", "Manage auditing and security log"),
    (
        9,
        "SeTakeOwnershipPrivilege",
        "Take ownership of files/objects",
    ),
    (
        10,
        "SeLoadDriverPrivilege",
        "Load and unload device drivers",
    ),
    (11, "SeSystemProfilePrivilege", "Profile system performance"),
    (12, "SeSystemtimePrivilege", "Change the system time"),
    (
        13,
        "SeProfileSingleProcessPrivilege",
        "Profile a single process",
    ),
    (
        14,
        "SeIncreaseBasePriorityPrivilege",
        "Increase scheduling priority",
    ),
    (15, "SeCreatePagefilePrivilege", "Create a pagefile"),
    (
        16,
        "SeCreatePermanentPrivilege",
        "Create permanent shared objects",
    ),
    (17, "SeBackupPrivilege", "Backup files and directories"),
    (18, "SeRestorePrivilege", "Restore files and directories"),
    (19, "SeShutdownPrivilege", "Shut down the system"),
    (20, "SeDebugPrivilege", "Debug programs"),
    (21, "SeAuditPrivilege", "Generate security audits"),
    (
        22,
        "SeSystemEnvironmentPrivilege",
        "Edit firmware environment values",
    ),
    (
        23,
        "SeChangeNotifyPrivilege",
        "Receive notifications of changes to files or directories",
    ),
    (
        24,
        "SeRemoteShutdownPrivilege",
        "Force shutdown from a remote system",
    ),
    (
        25,
        "SeUndockPrivilege",
        "Remove computer from docking station",
    ),
    (26, "SeSyncAgentPrivilege", "Synch directory service data"),
    (
        27,
        "SeEnableDelegationPrivilege",
        "Enable user accounts to be trusted for delegation",
    ),
    (
        28,
        "SeManageVolumePrivilege",
        "Manage the files on a volume",
    ),
    (
        29,
        "SeImpersonatePrivilege",
        "Impersonate a client after authentication",
    ),
    (30, "SeCreateGlobalPrivilege", "Create global objects"),
    (
        31,
        "SeTrustedCredManAccessPrivilege",
        "Access Credential Manager as a trusted caller",
    ),
    (
        32,
        "SeRelabelPrivilege",
        "Modify the mandatory integrity level of an object",
    ),
    (
        33,
        "SeIncreaseWorkingSetPrivilege",
        "Allocate more memory for user applications",
    ),
    (
        34,
        "SeTimeZonePrivilege",
        "Adjust the time zone of the computer's internal clock",
    ),
    (
        35,
        "SeCreateSymbolicLinkPrivilege",
        "Required to create a symbolic link",
    ),
    (
        36,
        "SeDelegateSessionUserImpersonatePrivilege",
        "Obtain an impersonation token for another user in the same session",
    ),
];

/// The constant name and description a privilege value names, when Windows
/// defines one.
///
/// `None` is a real answer: it means the token holds a bit this build of
/// Windows does not assign, which a report should show rather than hide.
pub fn privilege_name(value: u64) -> Option<(&'static str, &'static str)> {
    PRIVILEGES
        .iter()
        .find(|(candidate, _, _)| *candidate == value)
        .map(|(_, name, description)| (*name, *description))
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// How this build stores a token's privileges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegeShape {
    /// Vista and later: three 64-bit bitmaps, one bit per privilege value.
    Bitmaps {
        /// Path to the "is in the token at all" bitmap.
        present: String,
        /// Path to the "active now" bitmap.
        enabled: String,
        /// Path to the "comes up active" bitmap.
        enabled_by_default: String,
    },
    /// XP and 2003: a counted array of `_LUID_AND_ATTRIBUTES`.
    Array {
        /// Path to the pointer to the first element.
        pointer: String,
        /// Path to the element count.
        count: String,
        /// Declared size of one element, so the array can be strided.
        element_size: u64,
        /// Path to the privilege value inside an element.
        luid: String,
        /// Path to the attribute flags inside an element.
        attributes: String,
    },
}

impl PrivilegeShape {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            PrivilegeShape::Bitmaps { .. } => "bitmaps",
            PrivilegeShape::Array { .. } => "array",
        }
    }

    /// Whether this shape can say that a privilege is *absent* from a token.
    ///
    /// Only the bitmaps can: an array lists what is there and is silent about
    /// everything else.
    pub fn reports_absence(&self) -> bool {
        matches!(self, PrivilegeShape::Bitmaps { .. })
    }
}

/// The member paths one image's token privileges are read through.
#[derive(Debug, Clone)]
pub struct PrivilegeSymbols {
    /// Which of the two storage shapes this build uses.
    pub shape: PrivilegeShape,
}

impl PrivilegeSymbols {
    /// Resolve how this build stores privileges.
    ///
    /// # Errors
    ///
    /// [`TokenError::Unsupported`] naming every member that was tried, when the
    /// symbol table describes neither shape. A build whose privileges cannot be
    /// located must produce a refusal, never an empty privilege list.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, TokenError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        if !profile.symbols.has_type(TYPE_TOKEN) {
            return Err(TokenError::unsupported(format!(
                "the symbol table has no '{TYPE_TOKEN}', so a process's privileges cannot be read"
            )));
        }

        // The bitmap shape first: a build that has both is the later one, and
        // reading the pointer shape from it would dereference a bitmap.
        let present = first_member(
            &reader,
            TYPE_TOKEN,
            &["Privileges.Present", "Privileges.PresentPrivileges"],
        )?;
        let enabled = first_member(
            &reader,
            TYPE_TOKEN,
            &["Privileges.Enabled", "Privileges.EnabledPrivileges"],
        )?;
        let enabled_by_default =
            first_member(&reader, TYPE_TOKEN, &["Privileges.EnabledByDefault"])?;
        if let (Some(present), Some(enabled), Some(enabled_by_default)) =
            (present, enabled, enabled_by_default)
        {
            return Ok(Self {
                shape: PrivilegeShape::Bitmaps {
                    present: present.to_string(),
                    enabled: enabled.to_string(),
                    enabled_by_default: enabled_by_default.to_string(),
                },
            });
        }

        // The XP shape. Both the pointer and the count are required: a count
        // without a pointer cannot be walked, and a pointer without a count
        // cannot be bounded, and an unbounded walk over an image-derived
        // pointer is not an analysis.
        let pointer = first_member(&reader, TYPE_TOKEN, &["Privileges"])?;
        let count = first_member(&reader, TYPE_TOKEN, &["PrivilegeCount"])?;
        if let (Some(pointer), Some(count)) = (pointer, count) {
            // Required, and correctly so: the array is stepped through by this
            // width. The `has_type` guard that used to stand here answered
            // "this build has no such type" for a name the table declares twice
            // and refuses to disambiguate, which is a claim about the suspect's
            // machine made from a table this analysis could not read.
            let element_size = required_size(
                &profile.symbols,
                STAGE_HANDLES,
                &[TYPE_LUID_AND_ATTRIBUTES],
                "the array this build stores a token's privileges in has no element width, so no \
                 privilege beyond the first can be located and a process would be reported as \
                 holding almost none",
            )?;
            if element_size == 0 {
                return Err(TokenError::unsupported(format!(
                    "'{TYPE_LUID_AND_ATTRIBUTES}' declares a size of 0, so every element of the \
                     privilege array would be read at the same address"
                )));
            }
            let luid = first_member(&reader, TYPE_LUID_AND_ATTRIBUTES, &["Luid.LowPart", "Luid"])?
                .ok_or_else(|| {
                    TokenError::unsupported(format!(
                        "'{TYPE_LUID_AND_ATTRIBUTES}' has no Luid.LowPart, so a privilege in the \
                         array cannot be identified"
                    ))
                })?
                .to_string();
            let attributes = first_member(&reader, TYPE_LUID_AND_ATTRIBUTES, &["Attributes"])?
                .ok_or_else(|| {
                    TokenError::unsupported(format!(
                        "'{TYPE_LUID_AND_ATTRIBUTES}' has no Attributes, so whether a privilege was \
                         enabled cannot be told"
                    ))
                })?
                .to_string();
            return Ok(Self {
                shape: PrivilegeShape::Array {
                    pointer: pointer.to_string(),
                    count: count.to_string(),
                    element_size,
                    luid,
                    attributes,
                },
            });
        }

        Err(TokenError::unsupported(format!(
            "'{TYPE_TOKEN}' has neither the Vista bitmaps (Privileges.Present, Privileges.Enabled, \
             Privileges.EnabledByDefault) nor the XP array (Privileges with PrivilegeCount), so \
             this build's privileges cannot be read"
        )))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match &self.shape {
            PrivilegeShape::Bitmaps {
                present,
                enabled,
                enabled_by_default,
            } => serde_json::json!({
                "shape": "bitmaps",
                "present": present,
                "enabled": enabled,
                "enabled_by_default": enabled_by_default,
            }),
            PrivilegeShape::Array {
                pointer,
                count,
                element_size,
                luid,
                attributes,
            } => serde_json::json!({
                "shape": "array",
                "pointer": pointer,
                "count": count,
                "element_size": element_size,
                "luid": luid,
                "attributes": attributes,
            }),
        }
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One privilege, and the three separate things a token says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeRecord {
    /// The value stored in the token: the `LUID` low part.
    pub value: u64,
    /// The `Se…Privilege` constant, when Windows defines one for this value.
    /// `None` means the token holds a bit no shipping build assigns.
    pub name: Option<&'static str>,
    /// What the privilege permits, in the examiner's terms.
    pub description: Option<&'static str>,
    /// Whether the privilege is in the token at all.
    pub present: bool,
    /// Whether it was active when the image was taken.
    pub enabled: bool,
    /// Whether it comes up active every time the token is used.
    pub enabled_by_default: bool,
}

impl PrivilegeRecord {
    /// The attributes a report renders beside the name.
    pub fn attributes(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.present {
            out.push("Present");
        }
        if self.enabled {
            out.push("Enabled");
        }
        if self.enabled_by_default {
            out.push("Default");
        }
        out
    }

    /// Whether Windows assigns this value a name.
    pub fn is_named(&self) -> bool {
        self.name.is_some()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "value": self.value,
            "name": self.name,
            "description": self.description,
            "present": self.present,
            "enabled": self.enabled,
            "enabled_by_default": self.enabled_by_default,
            "attributes": self.attributes(),
        })
    }
}

/// Caps for reading one token's privileges.
#[derive(Debug, Clone)]
pub struct PrivilegeConfig {
    /// Ceiling on entries read from an array-shaped privilege list.
    pub max_privileges: u64,
}

impl Default for PrivilegeConfig {
    fn default() -> Self {
        Self {
            max_privileges: MAX_PRIVILEGE_ARRAY,
        }
    }
}

/// One process's privileges, and everything the read could not do.
#[derive(Debug, Clone)]
pub struct PrivilegeOutcome {
    /// The `_EPROCESS` the token belongs to.
    pub process: u64,
    /// Where the token was, or why there was not one.
    pub token: ProcessToken,
    /// Which storage shape was read.
    pub shape: &'static str,
    /// Whether this shape can report a privilege as absent, which decides
    /// whether an unlisted privilege means "not held" or "not stated".
    pub reports_absence: bool,
    /// The privileges. On the bitmap builds this is all 64 bit positions,
    /// including the ones the token does not hold.
    pub privileges: Vec<PrivilegeRecord>,
    /// Whether an array-shaped list was cut off by
    /// [`PrivilegeConfig::max_privileges`]. The token held more.
    pub truncated: bool,
    /// Everything odd that did not stop the read.
    pub notes: Vec<String>,
}

impl PrivilegeOutcome {
    /// Whether the token was read end to end.
    ///
    /// The question a report must ask before writing "this process did not hold
    /// `SeDebugPrivilege`": a token that could not be read says nothing about
    /// what was in it.
    pub fn is_complete(&self) -> bool {
        !self.truncated && !self.token.is_unavailable()
    }

    /// The privileges Windows names, which is what a report normally lists.
    pub fn named(&self) -> impl Iterator<Item = &PrivilegeRecord> {
        self.privileges.iter().filter(|record| record.is_named())
    }

    /// The privileges the token actually holds.
    pub fn held(&self) -> impl Iterator<Item = &PrivilegeRecord> {
        self.privileges.iter().filter(|record| record.present)
    }

    /// Whether a named privilege is present, when the evidence can answer.
    ///
    /// `None` covers both "the token could not be read" and "this build's
    /// storage shape cannot state an absence", either of which makes "no" a
    /// claim the evidence does not support.
    pub fn holds(&self, name: &str) -> Option<bool> {
        if self.token.is_unavailable() {
            return None;
        }
        match self
            .privileges
            .iter()
            .find(|record| record.name == Some(name))
        {
            Some(record) => Some(record.present),
            None if self.reports_absence => Some(false),
            None => None,
        }
    }

    /// Everything a report must declare about this result.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let ProcessToken::Unavailable(detail) = &self.token {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the token of the process at {:#x} could not be read, so its privileges are \
                     unknown rather than absent: {detail}",
                    self.process
                ),
            ));
        }
        if self.truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the privilege array of the process at {:#x} was cut off at its cap; the token \
                     lists more",
                    self.process
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "token": self.token.to_json(),
            "shape": self.shape,
            "reports_absence": self.reports_absence,
            "privileges": self.privileges.iter().map(PrivilegeRecord::to_json).collect::<Vec<_>>(),
            "privilege_count": self.privileges.len(),
            "truncated": self.truncated,
            "complete": self.is_complete(),
            "notes": self.notes,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── The read ────────────────────────────────────────────────────────────────

/// Read one process's token privileges.
///
/// `process` is the address of an `_EPROCESS` in the **kernel** address space.
///
/// # Errors
///
/// Only for failures that make the read meaningless: an `_EPROCESS` the symbols
/// cannot describe. A process without a token, or with one that could not be
/// read, is an outcome carrying [`ProcessToken`] and an empty list — never an
/// error, and never an empty list on its own.
pub fn list_privileges(
    profile: &WindowsProfile,
    token_symbols: &TokenSymbols,
    symbols: &PrivilegeSymbols,
    process: u64,
    config: &PrivilegeConfig,
) -> Result<PrivilegeOutcome, TokenError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let token = crate::handles::token::token_for(&reader, token_symbols, process)?;

    let mut outcome = PrivilegeOutcome {
        process,
        token: token.clone(),
        shape: symbols.shape.as_str(),
        reports_absence: symbols.shape.reports_absence(),
        privileges: Vec::new(),
        truncated: false,
        notes: Vec::new(),
    };
    let Some(address) = token.address() else {
        return Ok(outcome);
    };

    let token_object = match reader.object(address, TYPE_TOKEN) {
        Ok(object) => object,
        Err(err) => {
            outcome.token = ProcessToken::Unavailable(err.to_string());
            return Ok(outcome);
        }
    };

    match &symbols.shape {
        PrivilegeShape::Bitmaps {
            present,
            enabled,
            enabled_by_default,
        } => {
            let read = |path: &str| -> Result<u64, String> {
                token_object
                    .int(path)
                    .map_err(|err| format!("'{path}' could not be read: {err}"))?
                    .as_u64()
                    .ok_or_else(|| format!("'{path}' is negative, which is not a bitmap"))
            };
            // All three bitmaps or none. Reading two of three would put every
            // privilege's third column at whatever the default happens to be,
            // which reads as a stated fact about the token.
            let present = match read(present) {
                Ok(value) => value,
                Err(detail) => {
                    outcome.token = ProcessToken::Unavailable(detail);
                    return Ok(outcome);
                }
            };
            let enabled = match read(enabled) {
                Ok(value) => value,
                Err(detail) => {
                    outcome.token = ProcessToken::Unavailable(detail);
                    return Ok(outcome);
                }
            };
            let by_default = match read(enabled_by_default) {
                Ok(value) => value,
                Err(detail) => {
                    outcome.token = ProcessToken::Unavailable(detail);
                    return Ok(outcome);
                }
            };

            for value in 0..PRIVILEGE_BITS {
                let bit = 1u64 << value;
                let named = privilege_name(value);
                outcome.privileges.push(PrivilegeRecord {
                    value,
                    name: named.map(|(name, _)| name),
                    description: named.map(|(_, description)| description),
                    present: present & bit != 0,
                    enabled: enabled & bit != 0,
                    enabled_by_default: by_default & bit != 0,
                });
            }
        }
        PrivilegeShape::Array {
            pointer,
            count,
            element_size,
            luid,
            attributes,
        } => {
            let declared = match token_object.int(count) {
                Ok(value) => value.as_u64().unwrap_or(0),
                Err(err) => {
                    outcome.token =
                        ProcessToken::Unavailable(format!("'{count}' could not be read: {err}"));
                    return Ok(outcome);
                }
            };
            let base = match token_object.pointer(pointer) {
                Ok(value) => value,
                Err(err) => {
                    outcome.token =
                        ProcessToken::Unavailable(format!("'{pointer}' could not be read: {err}"));
                    return Ok(outcome);
                }
            };
            if base == 0 {
                if declared != 0 {
                    outcome.notes.push(format!(
                        "the token claims {declared} privilege(s) and its privilege array pointer \
                         is null, so the two disagree and neither is reported"
                    ));
                }
                return Ok(outcome);
            }
            let mut wanted = declared;
            if wanted > config.max_privileges {
                outcome.truncated = true;
                outcome.notes.push(format!(
                    "the token claims {declared} privilege(s), which is more than a token holds; \
                     only the first {} are read",
                    config.max_privileges
                ));
                wanted = config.max_privileges;
            }

            for index in 0..wanted {
                let Some(offset) = index.checked_mul(*element_size) else {
                    outcome.truncated = true;
                    outcome
                        .notes
                        .push("the privilege array wraps the address space".to_string());
                    break;
                };
                let Some(element) = base.checked_add(offset) else {
                    outcome.truncated = true;
                    outcome
                        .notes
                        .push("the privilege array wraps the address space".to_string());
                    break;
                };
                let object = match reader.object(element, TYPE_LUID_AND_ATTRIBUTES) {
                    Ok(object) => object,
                    Err(err) => {
                        outcome.truncated = true;
                        outcome.notes.push(format!(
                            "privilege {index} at {element:#x} could not be read, so it and every \
                             one after it are not listed: {err}"
                        ));
                        break;
                    }
                };
                let value = match object.int(luid).ok().and_then(|value| value.as_u64()) {
                    Some(value) => value,
                    None => {
                        outcome.truncated = true;
                        outcome.notes.push(format!(
                            "privilege {index} at {element:#x} has no readable value, so it and \
                             every one after it are not listed"
                        ));
                        break;
                    }
                };
                let flags = object
                    .int(attributes)
                    .ok()
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0);
                let named = privilege_name(value);
                outcome.privileges.push(PrivilegeRecord {
                    value,
                    name: named.map(|(name, _)| name),
                    description: named.map(|(_, description)| description),
                    // The array lists only what the token holds, so every
                    // element of it is present by construction.
                    present: true,
                    enabled: flags & SE_PRIVILEGE_ENABLED != 0,
                    enabled_by_default: flags & SE_PRIVILEGE_ENABLED_BY_DEFAULT != 0,
                });
            }
        }
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handles::test_support::{
        win10_profile, win10_profile_without, xp_profile, xp_profile_without, WIN10_EPROCESS,
        XP_EPROCESS,
    };

    fn win10() -> (WindowsProfile, TokenSymbols, PrivilegeSymbols) {
        let profile = win10_profile();
        let token = TokenSymbols::from_profile(&profile).expect("the token layout resolves");
        let privileges =
            PrivilegeSymbols::from_profile(&profile).expect("the privilege layout resolves");
        (profile, token, privileges)
    }

    #[test]
    fn the_privilege_table_has_no_duplicate_values() {
        for (index, (value, _, _)) in PRIVILEGES.iter().enumerate() {
            assert!(
                !PRIVILEGES[..index]
                    .iter()
                    .any(|(other, _, _)| other == value),
                "privilege value {value} appears twice"
            );
        }
    }

    #[test]
    fn a_bitmap_build_reports_every_bit_position_so_an_absence_is_stated() {
        let (profile, token, symbols) = win10();
        assert!(symbols.shape.reports_absence());
        let outcome = list_privileges(
            &profile,
            &token,
            &symbols,
            WIN10_EPROCESS,
            &PrivilegeConfig::default(),
        )
        .expect("the token reads");

        assert_eq!(outcome.privileges.len(), PRIVILEGE_BITS as usize);
        assert_eq!(outcome.named().count(), PRIVILEGES.len());
        assert!(outcome.is_complete());
    }

    #[test]
    fn present_enabled_and_enabled_by_default_are_carried_separately() {
        let (profile, token, symbols) = win10();
        let outcome = list_privileges(
            &profile,
            &token,
            &symbols,
            WIN10_EPROCESS,
            &PrivilegeConfig::default(),
        )
        .expect("the token reads");

        // The fixture sets bits 20 and 23 present, 20 enabled, 23 default.
        let debug = outcome
            .privileges
            .iter()
            .find(|record| record.value == 20)
            .expect("bit 20 is reported");
        assert_eq!(debug.name, Some("SeDebugPrivilege"));
        assert!(debug.present && debug.enabled && !debug.enabled_by_default);
        assert_eq!(debug.attributes(), vec!["Present", "Enabled"]);

        let notify = outcome
            .privileges
            .iter()
            .find(|record| record.value == 23)
            .expect("bit 23 is reported");
        assert_eq!(notify.name, Some("SeChangeNotifyPrivilege"));
        assert!(notify.present && !notify.enabled && notify.enabled_by_default);

        let load_driver = outcome
            .privileges
            .iter()
            .find(|record| record.value == 10)
            .expect("bit 10 is reported");
        assert!(!load_driver.present, "the fixture does not set bit 10");
        assert_eq!(outcome.holds("SeLoadDriverPrivilege"), Some(false));
        assert_eq!(outcome.holds("SeDebugPrivilege"), Some(true));
    }

    #[test]
    fn an_unassigned_bit_is_reported_without_a_name_rather_than_dropped() {
        let (profile, token, symbols) = win10();
        let outcome = list_privileges(
            &profile,
            &token,
            &symbols,
            WIN10_EPROCESS,
            &PrivilegeConfig::default(),
        )
        .expect("the token reads");
        let unassigned = outcome
            .privileges
            .iter()
            .find(|record| record.value == 63)
            .expect("bit 63 is reported");
        assert_eq!(unassigned.name, None);
        assert_eq!(unassigned.description, None);
    }

    #[test]
    fn an_array_build_lists_only_the_privileges_the_token_holds() {
        let profile = xp_profile();
        let token = TokenSymbols::from_profile(&profile).expect("the token layout resolves");
        let symbols =
            PrivilegeSymbols::from_profile(&profile).expect("the privilege layout resolves");
        assert!(
            !symbols.shape.reports_absence(),
            "an array cannot state an absence"
        );

        let outcome = list_privileges(
            &profile,
            &token,
            &symbols,
            XP_EPROCESS,
            &PrivilegeConfig::default(),
        )
        .expect("the token reads");
        assert_eq!(outcome.privileges.len(), 2);
        assert_eq!(outcome.privileges[0].value, 20);
        assert!(outcome.privileges[0].present && outcome.privileges[0].enabled);
        assert!(!outcome.privileges[0].enabled_by_default);
        assert_eq!(outcome.privileges[1].value, 23);
        assert!(outcome.privileges[1].enabled && outcome.privileges[1].enabled_by_default);

        // An array says nothing about a privilege it does not list, and the
        // API must not turn that silence into "no".
        assert_eq!(outcome.holds("SeLoadDriverPrivilege"), None);
        assert_eq!(outcome.holds("SeDebugPrivilege"), Some(true));
    }

    #[test]
    fn an_array_longer_than_the_cap_is_truncated_and_says_so() {
        let profile = xp_profile();
        let token = TokenSymbols::from_profile(&profile).expect("the token layout resolves");
        let symbols =
            PrivilegeSymbols::from_profile(&profile).expect("the privilege layout resolves");
        let outcome = list_privileges(
            &profile,
            &token,
            &symbols,
            XP_EPROCESS,
            &PrivilegeConfig { max_privileges: 1 },
        )
        .expect("the token reads");
        assert_eq!(outcome.privileges.len(), 1);
        assert!(outcome.truncated);
        assert!(!outcome.is_complete());
        assert!(!outcome.incomplete().is_empty());
    }

    #[test]
    fn a_process_whose_token_could_not_be_read_yields_no_privileges_and_an_incompleteness() {
        let (profile, token, symbols) = win10();
        let outcome = list_privileges(
            &profile,
            &token,
            &symbols,
            0x00FF_0000,
            &PrivilegeConfig::default(),
        )
        .expect("the stage still runs");
        assert!(outcome.privileges.is_empty());
        assert!(outcome.token.is_unavailable());
        assert!(!outcome.is_complete());
        assert_eq!(outcome.holds("SeDebugPrivilege"), None);
        assert!(!outcome.incomplete().is_empty());
    }

    #[test]
    fn a_build_with_neither_storage_shape_is_refused_naming_both() {
        let profile = win10_profile_without(&["_SEP_TOKEN_PRIVILEGES"]);
        let err = PrivilegeSymbols::from_profile(&profile).expect_err("the build is refused");
        let text = err.to_string();
        assert!(text.contains("Privileges.Present"), "{text}");
        assert!(text.contains("PrivilegeCount"), "{text}");
    }

    /// The array shape is only reached on a build with no Vista bitmaps, so
    /// this refusal can only be proved on the XP fixture.
    ///
    /// Fatal is right — the array is stepped by this width — but the sentence
    /// has to name the stage that stopped and what stopping cost, which a bare
    /// `SymbolError` through a transparent variant does not.
    #[test]
    fn an_array_build_without_the_element_type_names_the_stage_and_what_is_lost() {
        let profile = xp_profile_without(&["_LUID_AND_ATTRIBUTES"]);
        let err = PrivilegeSymbols::from_profile(&profile).expect_err("the build is refused");
        assert_eq!(err.class(), "required_not_declared");
        let text = err.to_string();
        assert!(text.contains("_LUID_AND_ATTRIBUTES"), "{text}");
        assert!(text.contains(STAGE_HANDLES.key), "{text}");
        assert!(
            text.contains("no privilege beyond the first can be located"),
            "the refusal must say what it cost: {text}"
        );
    }
}
