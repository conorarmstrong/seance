//! Token SIDs: which account a process was running as, and which groups it was
//! in.
//!
//! A process's identity on Windows is not its user name. It is a set of
//! security identifiers in its token: one for the account, and one for every
//! group whose membership the account carries. `S-1-5-18` is Local System.
//! `S-1-5-21-…-500` is the built-in Administrator of some particular machine or
//! domain. `S-1-5-32-544` is the Administrators group. An examiner asking "was
//! this running as the suspect's user, or as a service account that anyone on
//! the box could have driven?" is asking about this array and nothing else.
//!
//! # A SID is a structure, and rendering it wrong changes who it names
//!
//! ```text
//!   Revision  SubAuthorityCount   IdentifierAuthority (6 bytes, BIG-endian)
//!      1              5                00 00 00 00 00 05
//!   SubAuthority[0..count]  (32-bit, little-endian)
//!      21, 1004336348, 1177238915, 1801674531, 1001
//!   →  S-1-5-21-1004336348-1177238915-1801674531-1001
//! ```
//!
//! Three things here are easy to get wrong and every one of them produces a
//! string that still looks like a SID:
//!
//! * **The identifier authority is 48 bits, big-endian**, inside a structure
//!   whose every other field is little-endian. Upstream Volatility keeps only
//!   the last of the six bytes, which is right for every authority Windows
//!   actually issues (0 to 18) and silently wrong for anything else. This module
//!   composes all six bytes, and renders an authority that does not fit in 32
//!   bits as hex, which is what `ConvertSidToStringSid` does.
//! * **`SubAuthorityCount` is the length of a variable-length array** whose
//!   declared size in the symbol table is 1. Reading it as declared truncates
//!   every domain SID to `S-1-5-21`, which names a domain rather than a user.
//! * **The count comes out of the image**, so it is checked against the 15 that
//!   `IsValidSid` allows before anything is read, not after.
//!
//! # Which names are known here, and which are not
//!
//! [`WELL_KNOWN_SIDS`] holds the SIDs that are the same on every Windows
//! installation, and [`SID_RULES`] holds the patterns for the ones whose domain
//! part varies but whose trailing relative identifier does not — `…-500` is
//! always the built-in Administrator of whatever domain precedes it.
//!
//! Two families are deliberately **not** compiled in:
//!
//! * **Per-machine user SIDs.** `S-1-5-21-…-1001` is a real user with a real
//!   name, and that name lives in the `ProfileList` key of this machine's
//!   SOFTWARE hive. Guessing it is not possible and inventing it is worse, so a
//!   caller that has read the registry supplies the mapping through
//!   [`SidConfig::extra_names`].
//! * **Service SIDs.** `S-1-5-80-…` is the SHA-1 of a service's name, and the
//!   set of services differs per machine. The same [`SidConfig::extra_names`]
//!   carries them.
//!
//! An unmapped SID is reported with `name` as `None`, never as an empty string:
//! "we do not know whose account this is" and "this account has no name" are
//! different statements.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::required_size;
use seance_memory::object::StructReader;
use seance_memory::Incomplete;

use crate::handles::token::{first_member, ProcessToken, TokenError, TokenSymbols, TYPE_TOKEN};
use crate::module::STAGE_HANDLES;
use crate::profile::WindowsProfile;

/// The security identifier itself.
pub const TYPE_SID: &str = "_SID";

/// One entry of a token's user-and-groups array.
pub const TYPE_SID_AND_ATTRIBUTES: &str = "_SID_AND_ATTRIBUTES";

/// The revision every SID Windows issues carries, in the low nibble of
/// `_SID.Revision`.
pub const SID_REVISION: u64 = 1;

/// The most sub-authorities a valid SID has, as `IsValidSid` defines it.
pub const MAX_SUB_AUTHORITIES: u64 = 15;

/// Width of one sub-authority in bytes.
pub const SUB_AUTHORITY_SIZE: u64 = 4;

/// Width of the identifier authority in bytes.
pub const IDENTIFIER_AUTHORITY_SIZE: u64 = 6;

/// Ceiling on entries this module will read from a token's group array.
///
/// A token carries an account, a handful of groups and an integrity level:
/// tens, not thousands. The count came out of the image, so it is bounded
/// before the array is walked.
pub const MAX_TOKEN_SIDS: u64 = 4096;

/// The count above which the array is refused outright rather than truncated.
///
/// A `UserAndGroupCount` at or above this is not a large token; it is the bytes
/// at that offset not being a count, which means the pointer beside it is not
/// an array either.
pub const IMPLAUSIBLE_SID_COUNT: u64 = 0xFFFF;

/// The largest identifier authority that renders as a decimal number.
///
/// Above it, `ConvertSidToStringSid` renders the authority as `0x` followed by
/// twelve hex digits, and so does this module.
pub const MAX_DECIMAL_AUTHORITY: u64 = 0xFFFF_FFFF;

// ── Names ───────────────────────────────────────────────────────────────────

/// The SIDs that mean the same thing on every Windows installation.
pub const WELL_KNOWN_SIDS: [(&str, &str); 86] = [
    ("S-1-0", "Null Authority"),
    ("S-1-0-0", "Nobody"),
    ("S-1-1", "World Authority"),
    ("S-1-1-0", "Everyone"),
    ("S-1-2", "Local Authority"),
    (
        "S-1-2-0",
        "Local (Users with the ability to log in locally)",
    ),
    (
        "S-1-2-1",
        "Console Logon (Users who are logged onto the physical console)",
    ),
    ("S-1-3", "Creator Authority"),
    ("S-1-3-0", "Creator Owner"),
    ("S-1-3-1", "Creator Group"),
    ("S-1-3-2", "Creator Owner Server"),
    ("S-1-3-3", "Creator Group Server"),
    ("S-1-3-4", "Owner Rights"),
    ("S-1-4", "Non-unique Authority"),
    ("S-1-5", "NT Authority"),
    ("S-1-5-1", "Dialup"),
    ("S-1-5-2", "Network"),
    ("S-1-5-3", "Batch"),
    ("S-1-5-4", "Interactive"),
    ("S-1-5-6", "Service"),
    ("S-1-5-7", "Anonymous"),
    ("S-1-5-8", "Proxy"),
    ("S-1-5-9", "Enterprise Domain Controllers"),
    ("S-1-5-10", "Principal Self"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-12", "Restricted Code"),
    ("S-1-5-13", "Terminal Server Users"),
    ("S-1-5-14", "Remote Interactive Logon"),
    ("S-1-5-15", "This Organization"),
    (
        "S-1-5-17",
        "This Organization (Used by the default IIS user)",
    ),
    ("S-1-5-18", "Local System"),
    ("S-1-5-19", "NT Authority"),
    ("S-1-5-20", "NT Authority"),
    ("S-1-5-21-0-0-0-496", "Compounded Authentication"),
    ("S-1-5-21-0-0-0-497", "Claims Valid"),
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-32-546", "Guests"),
    ("S-1-5-32-547", "Power Users"),
    ("S-1-5-32-548", "Account Operators"),
    ("S-1-5-32-549", "Server Operators"),
    ("S-1-5-32-550", "Print Operators"),
    ("S-1-5-32-551", "Backup Operators"),
    ("S-1-5-32-552", "Replicators"),
    (
        "S-1-5-32-554",
        "BUILTIN\\Pre-Windows 2000 Compatible Access",
    ),
    ("S-1-5-32-555", "BUILTIN\\Remote Desktop Users"),
    ("S-1-5-32-556", "BUILTIN\\Network Configuration Operators"),
    ("S-1-5-32-557", "BUILTIN\\Incoming Forest Trust Builders"),
    ("S-1-5-32-558", "BUILTIN\\Performance Monitor Users"),
    ("S-1-5-32-559", "BUILTIN\\Performance Log Users"),
    (
        "S-1-5-32-560",
        "BUILTIN\\Windows Authorization Access Group",
    ),
    ("S-1-5-32-561", "BUILTIN\\Terminal Server License Servers"),
    ("S-1-5-32-562", "BUILTIN\\Distributed COM Users"),
    ("S-1-5-32-568", "BUILTIN\\IIS IUSRS"),
    ("S-1-5-32-569", "Cryptographic Operators"),
    ("S-1-5-32-573", "BUILTIN\\Event Log Readers"),
    ("S-1-5-32-574", "BUILTIN\\Certificate Service DCOM Access"),
    ("S-1-5-32-575", "RDS Remote Application Services"),
    ("S-1-5-32-576", "RDS Endpoint Servers"),
    ("S-1-5-32-577", "RDS Management Servers"),
    ("S-1-5-32-578", "Hyper-V Admins"),
    ("S-1-5-32-579", "Access Control Assistance Ops"),
    ("S-1-5-32-580", "Remote Management Users"),
    ("S-1-5-33", "Write Restricted"),
    ("S-1-5-64-10", "NTLM Authentication"),
    ("S-1-5-64-14", "SChannel Authentication"),
    ("S-1-5-64-21", "Digest Authentication"),
    ("S-1-5-65-1", "This Organization Certificate (Kerberos PAC)"),
    ("S-1-5-80", "NT Service"),
    ("S-1-5-84-0-0-0-0-0", "Usermode Drivers"),
    (
        "S-1-5-86-1544737700-199408000-2549878335-3519669259-381336952",
        "WMI (Local Service)",
    ),
    (
        "S-1-5-86-615999462-62705297-2911207457-59056572-3668589837",
        "WMI (Network Service)",
    ),
    ("S-1-5-113", "Local Account"),
    ("S-1-5-114", "Local Account (Member of Administrators)"),
    ("S-1-5-1000", "Other Organization"),
    ("S-1-15-2-1", "Application Package Context"),
    ("S-1-16-0", "Untrusted Mandatory Level"),
    ("S-1-16-4096", "Low Mandatory Level"),
    ("S-1-16-8192", "Medium Mandatory Level"),
    ("S-1-16-8448", "Medium Plus Mandatory Level"),
    ("S-1-16-12288", "High Mandatory Level"),
    ("S-1-16-16384", "System Mandatory Level"),
    ("S-1-16-20480", "Protected Process Mandatory Level"),
    ("S-1-16-28672", "Secure Process Mandatory Level"),
    ("S-1-18-1", "Authentication Authority Asserted Identity"),
    ("S-1-18-2", "Service Asserted Identity"),
];

/// One family of SIDs whose domain part varies and whose meaning does not.
///
/// Expressed structurally rather than as a regular expression: the fields say
/// what a match means, which a pattern like `S-1-5-[0-9-]+-500$` does not, and
/// matching on the decoded numbers cannot be fooled by a rendered string that
/// happens to end in the right digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidRule {
    /// The identifier authority the SID must carry. Every rule here is under
    /// the NT authority, 5.
    pub authority: u64,
    /// The first sub-authority, when the family is anchored to one — 21 for the
    /// domain families, 5 for logon sessions.
    pub first: Option<u32>,
    /// The **last** sub-authority: the relative identifier that names the
    /// account or group within its domain.
    pub rid: Option<u32>,
    /// The fewest sub-authorities a member of this family has.
    pub min_sub_authorities: usize,
    /// What a match means.
    pub name: &'static str,
}

/// The varying-domain SID families, in the order they are tried.
///
/// Order is load-bearing where two rules could match the same SID: the first
/// match wins, exactly as it does upstream.
pub const SID_RULES: [SidRule; 19] = [
    rule(None, Some(500), 2, "Administrator"),
    rule(None, Some(501), 2, "Guest"),
    rule(None, Some(502), 2, "KRBTGT"),
    rule(None, Some(512), 2, "Domain Admins"),
    rule(None, Some(513), 2, "Domain Users"),
    rule(None, Some(514), 2, "Domain Guests"),
    rule(None, Some(515), 2, "Domain Computers"),
    rule(None, Some(516), 2, "Domain Controllers"),
    rule(None, Some(517), 2, "Cert Publishers"),
    rule(None, Some(520), 2, "Group Policy Creator Owners"),
    rule(None, Some(533), 2, "RAS and IAS Servers"),
    // `S-1-5-5-x-y`: a logon session, identified by its position rather than by
    // a trailing relative identifier.
    rule(Some(5), None, 3, "Logon Session"),
    rule(Some(21), Some(518), 3, "Schema Admins"),
    rule(Some(21), Some(519), 3, "Enterprise Admins"),
    rule(Some(21), Some(553), 3, "RAS Servers"),
    rule(
        Some(21),
        Some(498),
        3,
        "Enterprise Read-Only Domain Controllers",
    ),
    rule(Some(21), Some(521), 3, "Read-Only Domain Controllers"),
    rule(Some(21), Some(522), 3, "Cloneable Domain Controllers"),
    rule(Some(21), Some(525), 3, "Protected Users"),
];

/// Build a rule under the NT authority.
const fn rule(
    first: Option<u32>,
    rid: Option<u32>,
    min_sub_authorities: usize,
    name: &'static str,
) -> SidRule {
    SidRule {
        authority: 5,
        first,
        rid,
        min_sub_authorities,
        name,
    }
}

// ── The SID ─────────────────────────────────────────────────────────────────

/// One decoded security identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    /// `_SID.Revision`, which is 1 on every SID Windows issues.
    pub revision: u64,
    /// The 48-bit identifier authority, composed big-endian from its six bytes.
    pub authority: u64,
    /// The sub-authorities, in order. The last one is the relative identifier.
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// The standard `S-1-…` text form.
    ///
    /// Matches `ConvertSidToStringSid`: decimal components throughout, except
    /// an identifier authority above [`MAX_DECIMAL_AUTHORITY`], which renders as
    /// twelve hex digits behind `0x`.
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(16 + self.sub_authorities.len() * 11);
        out.push_str("S-");
        out.push_str(&self.revision.to_string());
        out.push('-');
        if self.authority > MAX_DECIMAL_AUTHORITY {
            out.push_str(&format!("0x{:012x}", self.authority));
        } else {
            out.push_str(&self.authority.to_string());
        }
        for sub in &self.sub_authorities {
            out.push('-');
            out.push_str(&sub.to_string());
        }
        out
    }

    /// The name this SID has on every Windows installation, if any.
    ///
    /// Checks the exact table first and the varying-domain families second,
    /// because `S-1-5-21-0-0-0-496` is an exact well-known SID that would
    /// otherwise be swallowed by a family rule.
    pub fn well_known_name(&self) -> Option<&'static str> {
        let text = self.to_text();
        if let Some((_, name)) = WELL_KNOWN_SIDS.iter().find(|(sid, _)| *sid == text) {
            return Some(name);
        }
        self.family_name()
    }

    /// The varying-domain family this SID belongs to, if any.
    pub fn family_name(&self) -> Option<&'static str> {
        SID_RULES
            .iter()
            .find(|rule| self.matches(rule))
            .map(|rule| rule.name)
    }

    /// Whether this SID belongs to a family.
    fn matches(&self, rule: &SidRule) -> bool {
        if self.authority != rule.authority || self.sub_authorities.len() < rule.min_sub_authorities
        {
            return false;
        }
        if let Some(first) = rule.first {
            if self.sub_authorities.first() != Some(&first) {
                return false;
            }
        }
        if let Some(rid) = rule.rid {
            if self.sub_authorities.last() != Some(&rid) {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// The member paths one image's token SIDs are read through.
#[derive(Debug, Clone)]
pub struct SidSymbols {
    /// Path to the pointer to the user-and-groups array on `_TOKEN`.
    pub user_and_groups: String,
    /// Path to that array's element count.
    pub count: String,
    /// Declared size of one `_SID_AND_ATTRIBUTES`, so the array can be strided.
    pub entry_size: u64,
    /// Path to the SID pointer inside an entry.
    pub sid: String,
    /// Path to the attribute flags inside an entry.
    pub attributes: Option<String>,
    /// Path to the revision inside a `_SID`.
    pub revision: String,
    /// Path to the sub-authority count inside a `_SID`.
    pub sub_authority_count: String,
    /// Path to the six identifier-authority bytes inside a `_SID`.
    pub identifier_authority: String,
    /// Path to the first sub-authority inside a `_SID`.
    pub sub_authority: String,
}

impl SidSymbols {
    /// Resolve how this build stores a token's SIDs.
    ///
    /// # Errors
    ///
    /// [`TokenError::Unsupported`] naming the type or member that is missing.
    /// Every member here is required: a SID cannot be rendered from a subset of
    /// its fields, and a partly-read SID names a different account.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, TokenError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        // `_SID_AND_ATTRIBUTES` is deliberately not in this list: it is bound
        // below through the binding, which says which stage stopped and what
        // stopping cost rather than only that a type was unknown.
        for type_name in [TYPE_TOKEN, TYPE_SID] {
            if !profile.symbols.has_type(type_name) {
                return Err(TokenError::unsupported(format!(
                    "the symbol table has no '{type_name}', so the accounts a process ran as \
                     cannot be read"
                )));
            }
        }

        let user_and_groups = first_member(&reader, TYPE_TOKEN, &["UserAndGroups"])?
            .ok_or_else(|| {
                TokenError::unsupported(format!(
                    "'{TYPE_TOKEN}' has no UserAndGroups, so a process's account and groups cannot \
                     be located"
                ))
            })?
            .to_string();
        let count = first_member(&reader, TYPE_TOKEN, &["UserAndGroupCount"])?
            .ok_or_else(|| {
                TokenError::unsupported(format!(
                    "'{TYPE_TOKEN}' has no UserAndGroupCount, so the group array has no length and \
                     walking it would be unbounded"
                ))
            })?
            .to_string();
        // Required, and correctly so: the group array is stepped through by
        // this width, and with no width there is no second group to read.
        let entry_size = required_size(
            &profile.symbols,
            STAGE_HANDLES,
            &[TYPE_SID_AND_ATTRIBUTES],
            "the array of a token's groups has no element width, so no group beyond the first can \
             be located and a process would be reported as belonging to almost none",
        )?;
        if entry_size == 0 {
            return Err(TokenError::unsupported(format!(
                "'{TYPE_SID_AND_ATTRIBUTES}' declares a size of 0, so every entry of the group \
                 array would be read at the same address"
            )));
        }
        let sid = first_member(&reader, TYPE_SID_AND_ATTRIBUTES, &["Sid"])?
            .ok_or_else(|| {
                TokenError::unsupported(format!(
                    "'{TYPE_SID_AND_ATTRIBUTES}' has no Sid, so the array's entries do not lead to \
                     a security identifier"
                ))
            })?
            .to_string();

        let revision = first_member(&reader, TYPE_SID, &["Revision"])?
            .ok_or_else(|| TokenError::unsupported(format!("'{TYPE_SID}' has no Revision")))?
            .to_string();
        let sub_authority_count = first_member(&reader, TYPE_SID, &["SubAuthorityCount"])?
            .ok_or_else(|| {
                TokenError::unsupported(format!(
                    "'{TYPE_SID}' has no SubAuthorityCount, so how much of a SID to read is unknown"
                ))
            })?
            .to_string();
        let identifier_authority = first_member(
            &reader,
            TYPE_SID,
            &["IdentifierAuthority.Value", "IdentifierAuthority"],
        )?
        .ok_or_else(|| {
            TokenError::unsupported(format!(
                "'{TYPE_SID}' has no IdentifierAuthority, so the authority a SID belongs to cannot \
                 be read"
            ))
        })?
        .to_string();
        let sub_authority = first_member(&reader, TYPE_SID, &["SubAuthority"])?
            .ok_or_else(|| {
                TokenError::unsupported(format!(
                    "'{TYPE_SID}' has no SubAuthority, so a SID would render as its authority alone"
                ))
            })?
            .to_string();

        Ok(Self {
            user_and_groups,
            count,
            entry_size,
            sid,
            attributes: first_member(&reader, TYPE_SID_AND_ATTRIBUTES, &["Attributes"])?
                .map(str::to_string),
            revision,
            sub_authority_count,
            identifier_authority,
            sub_authority,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "user_and_groups": self.user_and_groups,
            "count": self.count,
            "entry_size": self.entry_size,
            "sid": self.sid,
            "attributes": self.attributes,
            "revision": self.revision,
            "sub_authority_count": self.sub_authority_count,
            "identifier_authority": self.identifier_authority,
            "sub_authority": self.sub_authority,
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One SID from a token, with whatever is known about whose it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidRecord {
    /// Where the `_SID` was, in the kernel address space.
    pub address: u64,
    /// The decoded SID.
    pub sid: Sid,
    /// The `S-1-…` text form, which is what a report shows.
    pub text: String,
    /// Whose account or group it is, when it could be named. `None` is a real
    /// answer: an unnamed per-machine SID is still evidence.
    pub name: Option<String>,
    /// `_SID_AND_ATTRIBUTES.Attributes`, when this build records it.
    pub attributes: Option<u64>,
}

impl SidRecord {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "sid": self.text,
            "revision": self.sid.revision,
            "authority": self.sid.authority,
            "sub_authorities": self.sid.sub_authorities,
            "name": self.name,
            "attributes": self.attributes,
        })
    }
}

/// Caps and extra naming for reading one token's SIDs.
#[derive(Debug, Clone, Default)]
pub struct SidConfig {
    /// Ceiling on entries read from the group array. Zero means
    /// [`MAX_TOKEN_SIDS`].
    pub max_sids: u64,
    /// SID text to name, for the SIDs that are specific to this machine: the
    /// user profiles out of the SOFTWARE hive, and the service SIDs. Consulted
    /// after [`WELL_KNOWN_SIDS`] and before the family rules, so a caller can
    /// name an account without being able to override a name Windows fixes.
    pub extra_names: BTreeMap<String, String>,
}

impl SidConfig {
    /// The effective cap.
    pub fn cap(&self) -> u64 {
        if self.max_sids == 0 {
            MAX_TOKEN_SIDS
        } else {
            self.max_sids
        }
    }
}

/// One process's token SIDs, and everything the read could not do.
#[derive(Debug, Clone)]
pub struct SidOutcome {
    /// The `_EPROCESS` the token belongs to.
    pub process: u64,
    /// Where the token was, or why there was not one.
    pub token: ProcessToken,
    /// The SIDs, in the order the token lists them. The first is the account
    /// the process ran as; the rest are its groups.
    pub sids: Vec<SidRecord>,
    /// What `UserAndGroupCount` claimed, so a short list can be recognised.
    pub declared_count: Option<u64>,
    /// Why the walk stopped before the declared count, when it did.
    pub stopped: Option<String>,
    /// Whether [`SidConfig::cap`] fired.
    pub truncated: bool,
    /// Everything odd that did not stop the read.
    pub notes: Vec<String>,
}

impl SidOutcome {
    /// Whether every SID the token claimed was read.
    ///
    /// The question a report must ask before writing "this process was not a
    /// member of Administrators": a group list that stopped early says nothing
    /// about the groups past where it stopped.
    pub fn is_complete(&self) -> bool {
        !self.truncated
            && self.stopped.is_none()
            && !self.token.is_unavailable()
            && match self.declared_count {
                Some(declared) => self.sids.len() as u64 == declared,
                None => self.token.address().is_none(),
            }
    }

    /// The account the process ran as: the first entry of the array.
    pub fn user(&self) -> Option<&SidRecord> {
        self.sids.first()
    }

    /// Whether the token carries a SID, when the evidence can answer.
    ///
    /// `None` when the list is incomplete, because absence from a partial list
    /// is not absence from the token.
    pub fn carries(&self, text: &str) -> Option<bool> {
        if self.sids.iter().any(|record| record.text == text) {
            return Some(true);
        }
        if self.is_complete() {
            Some(false)
        } else {
            None
        }
    }

    /// Everything a report must declare about this result.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let ProcessToken::Unavailable(detail) = &self.token {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the token of the process at {:#x} could not be read, so the account it ran as \
                     is unknown: {detail}",
                    self.process
                ),
            ));
        }
        if let Some(stopped) = &self.stopped {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the SID list of the process at {:#x} stopped early, so its remaining groups \
                     are not listed: {stopped}",
                    self.process
                ),
            ));
        }
        if self.truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the SID list of the process at {:#x} was cut off at its cap; the token lists \
                     more",
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
            "sids": self.sids.iter().map(SidRecord::to_json).collect::<Vec<_>>(),
            "sid_count": self.sids.len(),
            "declared_count": self.declared_count,
            "stopped": self.stopped,
            "truncated": self.truncated,
            "complete": self.is_complete(),
            "notes": self.notes,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── The read ────────────────────────────────────────────────────────────────

/// Read one process's token SIDs.
///
/// `process` is the address of an `_EPROCESS` in the **kernel** address space.
///
/// # Errors
///
/// Only for failures that make the read meaningless: an `_EPROCESS` the symbols
/// cannot describe. A process without a readable token is an outcome carrying
/// [`ProcessToken`] and an empty list.
pub fn list_sids(
    profile: &WindowsProfile,
    token_symbols: &TokenSymbols,
    symbols: &SidSymbols,
    process: u64,
    config: &SidConfig,
) -> Result<SidOutcome, TokenError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let token = crate::handles::token::token_for(&reader, token_symbols, process)?;

    let mut outcome = SidOutcome {
        process,
        token: token.clone(),
        sids: Vec::new(),
        declared_count: None,
        stopped: None,
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

    let declared = match token_object.int(&symbols.count) {
        Ok(value) => value.as_u64().unwrap_or(0),
        Err(err) => {
            outcome.token =
                ProcessToken::Unavailable(format!("'{}' could not be read: {err}", symbols.count));
            return Ok(outcome);
        }
    };
    outcome.declared_count = Some(declared);
    // A count this large is not a token with many groups; it is the bytes at
    // that offset not being a count, which means the pointer beside it is not
    // an array. Reading it anyway would emit thousands of SIDs assembled from
    // unrelated memory.
    if declared >= IMPLAUSIBLE_SID_COUNT {
        outcome.stopped = Some(format!(
            "the token claims {declared} SID(s), which no token holds, so the array beside the \
             count is not believed"
        ));
        return Ok(outcome);
    }

    let base = match token_object.pointer(&symbols.user_and_groups) {
        Ok(value) => value,
        Err(err) => {
            outcome.token = ProcessToken::Unavailable(format!(
                "'{}' could not be read: {err}",
                symbols.user_and_groups
            ));
            return Ok(outcome);
        }
    };
    if base == 0 {
        if declared != 0 {
            outcome.stopped = Some(format!(
                "the token claims {declared} SID(s) and its array pointer is null, so the two \
                 disagree and neither is reported"
            ));
        }
        return Ok(outcome);
    }

    let mut wanted = declared;
    if wanted > config.cap() {
        outcome.truncated = true;
        wanted = config.cap();
    }

    for index in 0..wanted {
        let Some(entry) = index
            .checked_mul(symbols.entry_size)
            .and_then(|offset| base.checked_add(offset))
        else {
            outcome.stopped = Some("the SID array wraps the address space".to_string());
            break;
        };
        let entry_object = match reader.object(entry, TYPE_SID_AND_ATTRIBUTES) {
            Ok(object) => object,
            Err(err) => {
                outcome.stopped = Some(format!("entry {index} at {entry:#x} is unreadable: {err}"));
                break;
            }
        };
        let sid_address = match entry_object.pointer(&symbols.sid) {
            Ok(0) => {
                outcome.stopped = Some(format!(
                    "entry {index} at {entry:#x} carries a null SID pointer"
                ));
                break;
            }
            Ok(value) => value,
            Err(err) => {
                outcome.stopped = Some(format!(
                    "entry {index} at {entry:#x} has no readable SID pointer: {err}"
                ));
                break;
            }
        };
        let attributes = symbols
            .attributes
            .as_deref()
            .and_then(|path| entry_object.int(path).ok())
            .and_then(|value| value.as_u64());

        match decode_sid(&reader, symbols, sid_address) {
            Ok(sid) => {
                let text = sid.to_text();
                let name = sid
                    .well_known_name()
                    .map(str::to_string)
                    .or_else(|| config.extra_names.get(&text).cloned());
                outcome.sids.push(SidRecord {
                    address: sid_address,
                    sid,
                    text,
                    name,
                    attributes,
                });
            }
            Err(detail) => {
                // A malformed SID means the count over-ran the real array, so
                // everything after it is unrelated memory too. Stopping and
                // saying so beats emitting made-up identities.
                outcome.stopped = Some(format!(
                    "entry {index} points at {sid_address:#x}, which is not a SID: {detail}"
                ));
                break;
            }
        }
    }

    Ok(outcome)
}

/// Decode one `_SID`, refusing anything `IsValidSid` would refuse.
///
/// The revision and count checks are what stop a `UserAndGroupCount` that
/// over-ran its array from turning arbitrary memory into a list of accounts the
/// suspect's process was supposedly running as.
pub fn decode_sid(
    reader: &StructReader,
    symbols: &SidSymbols,
    address: u64,
) -> Result<Sid, String> {
    let sid = reader
        .object(address, TYPE_SID)
        .map_err(|err| err.to_string())?;

    let revision = sid
        .int(&symbols.revision)
        .map_err(|err| format!("the revision could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| "the revision is negative".to_string())?;
    // `IsValidSid` compares the low nibble, and so does this: the high nibble
    // has never been used and a build that starts using it must not make every
    // SID on the machine unreadable.
    if revision & 0xF != SID_REVISION {
        return Err(format!(
            "its revision is {revision}, and every SID Windows issues has revision {SID_REVISION}"
        ));
    }

    let count = sid
        .int(&symbols.sub_authority_count)
        .map_err(|err| format!("the sub-authority count could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| "the sub-authority count is negative".to_string())?;
    if count > MAX_SUB_AUTHORITIES {
        return Err(format!(
            "it claims {count} sub-authorities, and a SID has at most {MAX_SUB_AUTHORITIES}"
        ));
    }

    // Six bytes, big-endian, inside a structure that is little-endian
    // everywhere else. Reading them the other way round turns the NT authority
    // (5) into 0x0500_0000_0000.
    let authority_bytes = sid
        .bytes(&symbols.identifier_authority)
        .map_err(|err| format!("the identifier authority could not be read: {err}"))?;
    if authority_bytes.len() < IDENTIFIER_AUTHORITY_SIZE as usize {
        return Err(format!(
            "its identifier authority is {} byte(s) rather than {IDENTIFIER_AUTHORITY_SIZE}",
            authority_bytes.len()
        ));
    }
    let authority = authority_bytes
        .iter()
        .take(IDENTIFIER_AUTHORITY_SIZE as usize)
        .fold(0u64, |total, byte| (total << 8) | u64::from(*byte));

    // The array is declared with one element and holds `count`, so its address
    // is taken from the symbol table and strided by hand. Reading it as
    // declared truncates every domain SID to its domain.
    let first = sid
        .member_address(&symbols.sub_authority)
        .map_err(|err| format!("the sub-authority array could not be located: {err}"))?;
    let mut sub_authorities = Vec::with_capacity(count as usize);
    for index in 0..count {
        let at = index
            .checked_mul(SUB_AUTHORITY_SIZE)
            .and_then(|offset| first.checked_add(offset))
            .ok_or_else(|| "its sub-authorities wrap the address space".to_string())?;
        let bytes = reader
            .read_bytes(at, SUB_AUTHORITY_SIZE)
            .map_err(|err| format!("sub-authority {index} at {at:#x} could not be read: {err}"))?;
        sub_authorities.push(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }

    Ok(Sid {
        revision,
        authority,
        sub_authorities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handles::test_support::{
        win10_profile, win10_profile_without, xp_profile, WIN10_EPROCESS, XP_EPROCESS,
    };

    fn sid(authority: u64, subs: &[u32]) -> Sid {
        Sid {
            revision: 1,
            authority,
            sub_authorities: subs.to_vec(),
        }
    }

    #[test]
    fn a_sid_renders_in_the_standard_text_form() {
        assert_eq!(sid(5, &[18]).to_text(), "S-1-5-18");
        assert_eq!(sid(5, &[32, 544]).to_text(), "S-1-5-32-544");
        assert_eq!(sid(0, &[0]).to_text(), "S-1-0-0");
        assert_eq!(
            sid(5, &[21, 1004336348, 1177238915, 1801674531, 1001]).to_text(),
            "S-1-5-21-1004336348-1177238915-1801674531-1001"
        );
    }

    #[test]
    fn an_identifier_authority_too_large_for_a_decimal_renders_as_hex() {
        // What `ConvertSidToStringSid` does, and the reason the authority is
        // carried as 48 bits rather than as one byte.
        assert_eq!(
            sid(0x0001_0000_0000, &[1]).to_text(),
            "S-1-0x000100000000-1"
        );
    }

    #[test]
    fn well_known_sids_are_named_and_unknown_ones_are_not_invented() {
        assert_eq!(sid(5, &[18]).well_known_name(), Some("Local System"));
        assert_eq!(sid(5, &[32, 544]).well_known_name(), Some("Administrators"));
        assert_eq!(
            sid(16, &[12288]).well_known_name(),
            Some("High Mandatory Level")
        );
        assert_eq!(sid(5, &[21, 1, 2, 3, 1001]).well_known_name(), None);
    }

    #[test]
    fn a_varying_domain_sid_is_named_by_its_relative_identifier() {
        assert_eq!(
            sid(5, &[21, 1, 2, 3, 500]).well_known_name(),
            Some("Administrator")
        );
        assert_eq!(
            sid(5, &[21, 1, 2, 3, 513]).well_known_name(),
            Some("Domain Users")
        );
        assert_eq!(
            sid(5, &[21, 1, 2, 3, 519]).well_known_name(),
            Some("Enterprise Admins")
        );
        assert_eq!(
            sid(5, &[5, 0, 123456]).well_known_name(),
            Some("Logon Session")
        );
    }

    #[test]
    fn an_exact_well_known_sid_wins_over_a_family_that_would_also_match() {
        // `S-1-5-21-0-0-0-496` ends in 496, which no family claims, but the
        // ordering is what stops a future family rule from renaming it.
        assert_eq!(
            sid(5, &[21, 0, 0, 0, 496]).well_known_name(),
            Some("Compounded Authentication")
        );
    }

    #[test]
    fn a_family_needs_enough_sub_authorities_to_have_a_domain_part() {
        // `S-1-5-500` is the NT authority with a single component: there is no
        // domain in front of the 500, so it is not the built-in Administrator
        // of anything.
        assert_eq!(sid(5, &[500]).well_known_name(), None);
    }

    #[test]
    fn a_family_rule_does_not_fire_under_another_authority() {
        assert_eq!(sid(4, &[21, 1, 2, 3, 500]).well_known_name(), None);
    }

    #[test]
    fn the_sids_of_a_token_are_read_in_order_with_the_account_first() {
        let profile = win10_profile();
        let token = TokenSymbols::from_profile(&profile).expect("the token layout resolves");
        let symbols = SidSymbols::from_profile(&profile).expect("the SID layout resolves");
        let outcome = list_sids(
            &profile,
            &token,
            &symbols,
            WIN10_EPROCESS,
            &SidConfig::default(),
        )
        .expect("the token reads");

        assert!(outcome.is_complete(), "{:?}", outcome.stopped);
        let texts: Vec<&str> = outcome.sids.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, vec!["S-1-5-18", "S-1-5-21-111-222-333-500"]);
        assert_eq!(
            outcome.user().and_then(|r| r.name.as_deref()),
            Some("Local System")
        );
        assert_eq!(outcome.sids[1].name.as_deref(), Some("Administrator"));
        assert_eq!(outcome.sids[0].attributes, Some(7));
        assert_eq!(outcome.carries("S-1-5-18"), Some(true));
        assert_eq!(outcome.carries("S-1-5-32-544"), Some(false));
    }

    #[test]
    fn a_multi_component_domain_sid_is_read_past_the_declared_array_length_of_one() {
        // `_SID.SubAuthority` is declared `[1]`; a reader that believed the
        // declaration would render every domain SID as `S-1-5-21`.
        let profile = win10_profile();
        let token = TokenSymbols::from_profile(&profile).expect("the token layout resolves");
        let symbols = SidSymbols::from_profile(&profile).expect("the SID layout resolves");
        let outcome = list_sids(
            &profile,
            &token,
            &symbols,
            WIN10_EPROCESS,
            &SidConfig::default(),
        )
        .expect("the token reads");
        assert_eq!(
            outcome.sids[1].sid.sub_authorities,
            vec![21, 111, 222, 333, 500]
        );
    }

    #[test]
    fn a_name_windows_fixes_is_not_overridden_by_a_caller_supplied_one() {
        let profile = win10_profile();
        let token = TokenSymbols::from_profile(&profile).expect("the token layout resolves");
        let symbols = SidSymbols::from_profile(&profile).expect("the SID layout resolves");
        let mut extra_names = BTreeMap::new();
        extra_names.insert("S-1-5-21-111-222-333-500".to_string(), "sarah".to_string());
        let outcome = list_sids(
            &profile,
            &token,
            &symbols,
            WIN10_EPROCESS,
            &SidConfig {
                max_sids: 0,
                extra_names,
            },
        )
        .expect("the token reads");
        // The family rule fixes this one, so a caller cannot override it: the
        // built-in Administrator is the built-in Administrator whatever the
        // profile directory is called.
        assert_eq!(outcome.sids[1].name.as_deref(), Some("Administrator"));
    }

    #[test]
    fn a_thirty_two_bit_token_reads_the_same_way() {
        let profile = xp_profile();
        let token = TokenSymbols::from_profile(&profile).expect("the token layout resolves");
        let symbols = SidSymbols::from_profile(&profile).expect("the SID layout resolves");
        let outcome = list_sids(
            &profile,
            &token,
            &symbols,
            XP_EPROCESS,
            &SidConfig::default(),
        )
        .expect("the token reads");
        assert_eq!(outcome.sids.len(), 1);
        assert_eq!(outcome.sids[0].text, "S-1-5-18");
    }

    #[test]
    fn a_cap_shorter_than_the_token_truncates_and_says_so() {
        let profile = win10_profile();
        let token = TokenSymbols::from_profile(&profile).expect("the token layout resolves");
        let symbols = SidSymbols::from_profile(&profile).expect("the SID layout resolves");
        let outcome = list_sids(
            &profile,
            &token,
            &symbols,
            WIN10_EPROCESS,
            &SidConfig {
                max_sids: 1,
                extra_names: BTreeMap::new(),
            },
        )
        .expect("the token reads");
        assert_eq!(outcome.sids.len(), 1);
        assert!(outcome.truncated);
        assert!(!outcome.is_complete());
        assert_eq!(
            outcome.carries("S-1-5-32-544"),
            None,
            "absence from a truncated list is not absence from the token"
        );
        assert!(!outcome.incomplete().is_empty());
    }

    #[test]
    fn a_structure_that_is_not_a_sid_is_refused_rather_than_rendered() {
        let profile = win10_profile();
        let symbols = SidSymbols::from_profile(&profile).expect("the SID layout resolves");
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        // A page of zeros has revision 0, which no SID has.
        let err = decode_sid(&reader, &symbols, 0).expect_err("a zeroed SID is refused");
        assert!(err.contains("revision"), "{err}");
    }

    #[test]
    fn a_sub_authority_count_above_fifteen_is_refused() {
        let profile = win10_profile();
        let symbols = SidSymbols::from_profile(&profile).expect("the SID layout resolves");
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let err = decode_sid(
            &reader,
            &symbols,
            crate::handles::test_support::WIN10_BAD_SID,
        )
        .expect_err("an over-long SID is refused");
        assert!(err.contains("sub-authorities"), "{err}");
    }

    #[test]
    fn a_build_without_a_sid_type_is_refused_by_name() {
        let profile = win10_profile_without(&["_SID"]);
        let err = SidSymbols::from_profile(&profile).expect_err("the build is refused");
        assert!(err.to_string().contains("_SID"), "{err}");
    }

    /// Fatal is right — the group array is stepped by this width — but the
    /// examiner has to be told which stage stopped and what stopping cost, not
    /// just that a type was unknown.
    #[test]
    fn a_build_without_the_group_entry_type_names_the_stage_and_what_is_lost() {
        let profile = win10_profile_without(&["_SID_AND_ATTRIBUTES"]);
        let err = SidSymbols::from_profile(&profile).expect_err("the build is refused");
        assert_eq!(err.class(), "required_not_declared");
        let text = err.to_string();
        assert!(text.contains("_SID_AND_ATTRIBUTES"), "{text}");
        assert!(text.contains(STAGE_HANDLES.key), "{text}");
        assert!(
            text.contains("no group beyond the first can be located"),
            "the refusal must say what it cost: {text}"
        );
    }
}
