//! Naming tables for Windows security descriptors: well-known SIDs, ACE types,
//! ACE/control flags and `ACCESS_MASK` bits.
//!
//! Every function here is a *presentation* aid over values the decoder already
//! recovered verbatim. None of them may invent a name: a SID that is not in
//! `[MS-DTYP]` §2.4.2.4 (a local or domain account, which cannot be resolved
//! from the volume's `$Secure` file alone) returns `None` and the examiner sees
//! the raw SID. A wrong answer here would put the wrong user's name against a
//! file, so "unknown" is always preferred to "plausible".
//!
//! Raw numeric values (`ace_type`, `flags`, `access_mask`) are always emitted
//! alongside these names, so a bit this table does not know about is still
//! visible in the artifact rather than silently dropped.

use super::Sid;

/// Identifier authority 5 (`SECURITY_NT_AUTHORITY`).
const NT_AUTHORITY: u64 = 5;
/// Identifier authority 16 (`SECURITY_MANDATORY_LABEL_AUTHORITY`).
const MANDATORY_LABEL_AUTHORITY: u64 = 16;
/// First sub-authority of a domain/machine SID (`S-1-5-21-…`).
const SECURITY_NT_NON_UNIQUE: u32 = 21;
/// First sub-authority of the BUILTIN domain (`S-1-5-32-…`).
const SECURITY_BUILTIN_DOMAIN: u32 = 32;
/// Relative identifiers below this are reserved by Windows; at or above it the
/// account is locally created and unnameable from the descriptor store alone.
const FIRST_UNRESERVED_RID: u32 = 1000;

/// Exact well-known SIDs, keyed by their string form ([MS-DTYP] §2.4.2.4).
///
/// Only universal, NT-authority and BUILTIN SIDs appear: those have the same
/// meaning on every Windows installation, so naming them from the SID alone is
/// sound. Domain-relative SIDs are handled by [`sid_friendly_name`] via their
/// RID, and everything else stays unnamed.
const WELL_KNOWN_SIDS: &[(&str, &str)] = &[
    // Universal authorities 0-4.
    ("S-1-0-0", "Null SID"),
    ("S-1-1-0", "Everyone"),
    ("S-1-2-0", "Local"),
    ("S-1-2-1", "Console Logon"),
    ("S-1-3-0", "Creator Owner"),
    ("S-1-3-1", "Creator Group"),
    ("S-1-3-2", "Creator Owner Server"),
    ("S-1-3-3", "Creator Group Server"),
    ("S-1-3-4", "Owner Rights"),
    // NT authority (S-1-5-*).
    ("S-1-5-1", "Dialup"),
    ("S-1-5-2", "Network"),
    ("S-1-5-3", "Batch"),
    ("S-1-5-4", "Interactive"),
    ("S-1-5-6", "Service"),
    ("S-1-5-7", "Anonymous Logon"),
    ("S-1-5-8", "Proxy"),
    ("S-1-5-9", "Enterprise Domain Controllers"),
    ("S-1-5-10", "Principal Self"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-12", "Restricted Code"),
    ("S-1-5-13", "Terminal Server User"),
    ("S-1-5-14", "Remote Interactive Logon"),
    ("S-1-5-15", "This Organization"),
    ("S-1-5-17", "IUSR"),
    ("S-1-5-18", "Local System"),
    ("S-1-5-19", "Local Service"),
    ("S-1-5-20", "Network Service"),
    ("S-1-5-33", "Write Restricted Code"),
    ("S-1-5-64-10", "NTLM Authentication"),
    ("S-1-5-64-14", "SChannel Authentication"),
    ("S-1-5-64-21", "Digest Authentication"),
    ("S-1-5-65-1", "This Organization Certificate"),
    ("S-1-5-80-0", "All Services"),
    ("S-1-5-83-0", "Virtual Machines"),
    ("S-1-5-84-0-0-0-0-0", "User Mode Drivers"),
    ("S-1-5-90-0", "Window Manager Group"),
    ("S-1-5-113", "Local Account"),
    (
        "S-1-5-114",
        "Local Account And Member Of Administrators Group",
    ),
    ("S-1-5-1000", "Other Organization"),
    // BUILTIN domain (S-1-5-32-*).
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-545", "Users"),
    ("S-1-5-32-546", "Guests"),
    ("S-1-5-32-547", "Power Users"),
    ("S-1-5-32-548", "Account Operators"),
    ("S-1-5-32-549", "Server Operators"),
    ("S-1-5-32-550", "Print Operators"),
    ("S-1-5-32-551", "Backup Operators"),
    ("S-1-5-32-552", "Replicators"),
    ("S-1-5-32-554", "Pre-Windows 2000 Compatible Access"),
    ("S-1-5-32-555", "Remote Desktop Users"),
    ("S-1-5-32-556", "Network Configuration Operators"),
    ("S-1-5-32-557", "Incoming Forest Trust Builders"),
    ("S-1-5-32-558", "Performance Monitor Users"),
    ("S-1-5-32-559", "Performance Log Users"),
    ("S-1-5-32-560", "Windows Authorization Access Group"),
    ("S-1-5-32-561", "Terminal Server License Servers"),
    ("S-1-5-32-562", "Distributed COM Users"),
    ("S-1-5-32-568", "IIS_IUSRS"),
    ("S-1-5-32-569", "Cryptographic Operators"),
    ("S-1-5-32-573", "Event Log Readers"),
    ("S-1-5-32-574", "Certificate Service DCOM Access"),
    ("S-1-5-32-575", "RDS Remote Access Servers"),
    ("S-1-5-32-576", "RDS Endpoint Servers"),
    ("S-1-5-32-577", "RDS Management Servers"),
    ("S-1-5-32-578", "Hyper-V Administrators"),
    ("S-1-5-32-579", "Access Control Assistance Operators"),
    ("S-1-5-32-580", "Remote Management Users"),
    ("S-1-5-32-581", "System Managed Accounts Group"),
    ("S-1-5-32-582", "Storage Replica Administrators"),
    // Application package authority.
    ("S-1-15-2-1", "All Application Packages"),
    ("S-1-15-2-2", "All Restricted Application Packages"),
    // Mandatory integrity levels (S-1-16-*).
    ("S-1-16-0", "Untrusted Mandatory Level"),
    ("S-1-16-4096", "Low Mandatory Level"),
    ("S-1-16-8192", "Medium Mandatory Level"),
    ("S-1-16-8448", "Medium Plus Mandatory Level"),
    ("S-1-16-12288", "High Mandatory Level"),
    ("S-1-16-16384", "System Mandatory Level"),
    ("S-1-16-20480", "Protected Process Mandatory Level"),
    ("S-1-16-28672", "Secure Process Mandatory Level"),
];

/// Reserved relative identifiers inside a domain or machine SID
/// (`S-1-5-21-<domain>-<RID>`). These mean the same thing in every domain, so
/// they can be named from the RID alone; anything from
/// [`FIRST_UNRESERVED_RID`] up is a locally created account whose name lives in
/// the SAM, not in `$Secure`, and stays unnamed.
const WELL_KNOWN_RIDS: &[(u32, &str)] = &[
    (498, "Enterprise Read-only Domain Controllers"),
    (500, "Administrator"),
    (501, "Guest"),
    (502, "krbtgt"),
    (512, "Domain Admins"),
    (513, "Domain Users"),
    (514, "Domain Guests"),
    (515, "Domain Computers"),
    (516, "Domain Controllers"),
    (517, "Cert Publishers"),
    (518, "Schema Admins"),
    (519, "Enterprise Admins"),
    (520, "Group Policy Creator Owners"),
    (521, "Read-only Domain Controllers"),
    (522, "Cloneable Domain Controllers"),
    (526, "Key Admins"),
    (527, "Enterprise Key Admins"),
    (553, "RAS and IAS Servers"),
    (571, "Allowed RODC Password Replication Group"),
    (572, "Denied RODC Password Replication Group"),
];

/// Integrity levels carried by a `SYSTEM_MANDATORY_LABEL` ACE, keyed by the
/// trustee SID's relative identifier (`S-1-16-<RID>`).
///
/// A Low label on a file is the "downloaded from the internet / written by a
/// sandboxed process" signal; High/System labels mark elevated content.
const INTEGRITY_LEVELS: &[(u32, &str)] = &[
    (0x0000, "Untrusted"),
    (0x1000, "Low"),
    (0x2000, "Medium"),
    (0x2100, "Medium Plus"),
    (0x3000, "High"),
    (0x4000, "System"),
    (0x5000, "Protected Process"),
    (0x7000, "Secure Process"),
];

/// ACE type values ([MS-DTYP] §2.4.4.1).
const ACE_TYPES: &[(u8, &str)] = &[
    (0x00, "ACCESS_ALLOWED_ACE_TYPE"),
    (0x01, "ACCESS_DENIED_ACE_TYPE"),
    (0x02, "SYSTEM_AUDIT_ACE_TYPE"),
    (0x03, "SYSTEM_ALARM_ACE_TYPE"),
    (0x04, "ACCESS_ALLOWED_COMPOUND_ACE_TYPE"),
    (0x05, "ACCESS_ALLOWED_OBJECT_ACE_TYPE"),
    (0x06, "ACCESS_DENIED_OBJECT_ACE_TYPE"),
    (0x07, "SYSTEM_AUDIT_OBJECT_ACE_TYPE"),
    (0x08, "SYSTEM_ALARM_OBJECT_ACE_TYPE"),
    (0x09, "ACCESS_ALLOWED_CALLBACK_ACE_TYPE"),
    (0x0A, "ACCESS_DENIED_CALLBACK_ACE_TYPE"),
    (0x0B, "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE"),
    (0x0C, "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE"),
    (0x0D, "SYSTEM_AUDIT_CALLBACK_ACE_TYPE"),
    (0x0E, "SYSTEM_ALARM_CALLBACK_ACE_TYPE"),
    (0x0F, "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE"),
    (0x10, "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE"),
    (0x11, "SYSTEM_MANDATORY_LABEL_ACE_TYPE"),
    (0x12, "SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE"),
    (0x13, "SYSTEM_SCOPED_POLICY_ID_ACE_TYPE"),
    (0x14, "SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE"),
    (0x15, "SYSTEM_ACCESS_FILTER_ACE_TYPE"),
];

/// ACE header flag bits ([MS-DTYP] §2.4.4.1). The last two are audit-only and
/// appear in a SACL.
const ACE_FLAGS: &[(u8, &str)] = &[
    (0x01, "OBJECT_INHERIT"),
    (0x02, "CONTAINER_INHERIT"),
    (0x04, "NO_PROPAGATE_INHERIT"),
    (0x08, "INHERIT_ONLY"),
    (0x10, "INHERITED"),
    (0x40, "SUCCESSFUL_ACCESS"),
    (0x80, "FAILED_ACCESS"),
];

/// Security descriptor control bits ([MS-DTYP] §2.4.6).
const CONTROL_FLAGS: &[(u16, &str)] = &[
    (0x0001, "SE_OWNER_DEFAULTED"),
    (0x0002, "SE_GROUP_DEFAULTED"),
    (0x0004, "SE_DACL_PRESENT"),
    (0x0008, "SE_DACL_DEFAULTED"),
    (0x0010, "SE_SACL_PRESENT"),
    (0x0020, "SE_SACL_DEFAULTED"),
    (0x0040, "SE_DACL_TRUSTED"),
    (0x0080, "SE_SERVER_SECURITY"),
    (0x0100, "SE_DACL_AUTO_INHERIT_REQ"),
    (0x0200, "SE_SACL_AUTO_INHERIT_REQ"),
    (0x0400, "SE_DACL_AUTO_INHERITED"),
    (0x0800, "SE_SACL_AUTO_INHERITED"),
    (0x1000, "SE_DACL_PROTECTED"),
    (0x2000, "SE_SACL_PROTECTED"),
    (0x4000, "SE_RM_CONTROL_VALID"),
    (0x8000, "SE_SELF_RELATIVE"),
];

/// A table of single bits and the names they carry.
///
/// Named so that the three tables below, and the two a renderer picks between,
/// read as one thing rather than as nested tuple types.
type BitNames = &'static [(u32, &'static str)];

/// Which kind of object a security descriptor was found on.
///
/// # Why the renderer cannot be asked without this
///
/// The low 16 bits of an `ACCESS_MASK` are **object-specific**. `0x1` is
/// `FILE_READ_DATA` on a file and `KEY_QUERY_VALUE` on a registry key; `0x2` is
/// `FILE_WRITE_DATA` and `KEY_SET_VALUE`. A renderer that does not know which
/// object it has cannot name those bits without guessing, and a guess here
/// prints a permission that is not in the evidence.
///
/// `$Secure:$SDS` describes files and directories; a hive's `sk` cells describe
/// registry keys. Both structures are the same NT security descriptor, which is
/// why one decoder serves both — and exactly why the decoder has to be told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// A file or directory, as `$Secure:$SDS` records.
    File,
    /// A registry key, as a hive's `sk` cells record.
    RegistryKey,
}

/// Registry-key access rights: the object-specific low bits of a key's
/// `ACCESS_MASK`.
///
/// From the `KEY_*` constants in `winnt.h`. The WOW64 bits are included
/// because a redirected key's ACL carries them and dropping them would leave an
/// unnamed bit on an ordinary mask.
const REGISTRY_RIGHT_BITS: &[(u32, &str)] = &[
    (0x0000_0001, "KEY_QUERY_VALUE"),
    (0x0000_0002, "KEY_SET_VALUE"),
    (0x0000_0004, "KEY_CREATE_SUB_KEY"),
    (0x0000_0008, "KEY_ENUMERATE_SUB_KEYS"),
    (0x0000_0010, "KEY_NOTIFY"),
    (0x0000_0020, "KEY_CREATE_LINK"),
    (0x0000_0100, "KEY_WOW64_64KEY"),
    (0x0000_0200, "KEY_WOW64_32KEY"),
];

/// Composite registry masks Windows presents as one permission.
///
/// Matched **exactly**, on the same rule as [`COMPOSITE_MASKS`]: a mask one bit
/// away from `KEY_ALL_ACCESS` is not `KEY_ALL_ACCESS` and must be spelled out.
///
/// `KEY_READ` and `KEY_EXECUTE` are the same value, `0x20019`, so there is one
/// entry for it rather than two — a table with both would name the value
/// arbitrarily and leave a reader thinking the other had been ruled out.
const REGISTRY_COMPOSITE_MASKS: &[(u32, &str)] = &[
    (0x000F_003F, "KEY_ALL_ACCESS"),
    (0x0002_0019, "KEY_READ"),
    (0x0002_0006, "KEY_WRITE"),
];

/// The composite name for a registry mask, if it is one exactly.
///
/// Exposed so a test can assert the table holds one entry per *value*.
pub fn registry_composite_name(mask: u32) -> Option<&'static str> {
    REGISTRY_COMPOSITE_MASKS
        .iter()
        .find(|(m, _)| *m == mask)
        .map(|(_, name)| *name)
}

/// Standard and generic rights, which mean the same thing on every object kind.
///
/// The generic bits are named **generically and never translated**. `GENERIC_ALL`
/// on a key becomes `KEY_ALL_ACCESS` only through the kernel's generic mapping
/// for the key object type, and that mapping is not in the hive: naming it as
/// the specific rights would assert something this tool did not read. It is not
/// a nicety either — `GENERIC_ALL` is the third most common mask across the
/// twelve real hives, 507 times in `SOFTWARE` alone.
const STANDARD_RIGHT_BITS: &[(u32, &str)] = &[
    (0x0001_0000, "DELETE"),
    (0x0002_0000, "READ_CONTROL"),
    (0x0004_0000, "WRITE_DAC"),
    (0x0008_0000, "WRITE_OWNER"),
    (0x0010_0000, "SYNCHRONIZE"),
    (0x0100_0000, "ACCESS_SYSTEM_SECURITY"),
    (0x0200_0000, "MAXIMUM_ALLOWED"),
    (0x1000_0000, "GENERIC_ALL"),
    (0x2000_0000, "GENERIC_EXECUTE"),
    (0x4000_0000, "GENERIC_WRITE"),
    (0x8000_0000, "GENERIC_READ"),
];

/// Individual `ACCESS_MASK` bits, named for a file/directory object (the only
/// kind `$Secure` describes). Bits 0-15 are object-specific and would mean
/// something else on a registry key or a service.
const ACCESS_RIGHT_BITS: &[(u32, &str)] = &[
    (0x0000_0001, "Read Data / List Directory"),
    (0x0000_0002, "Write Data / Create File"),
    (0x0000_0004, "Append Data / Create Subdirectory"),
    (0x0000_0008, "Read Extended Attributes"),
    (0x0000_0010, "Write Extended Attributes"),
    (0x0000_0020, "Execute / Traverse"),
    (0x0000_0040, "Delete Child"),
    (0x0000_0080, "Read Attributes"),
    (0x0000_0100, "Write Attributes"),
    (0x0001_0000, "Delete"),
    (0x0002_0000, "Read Permissions"),
    (0x0004_0000, "Change Permissions"),
    (0x0008_0000, "Take Ownership"),
    (0x0010_0000, "Synchronize"),
    (0x0100_0000, "Access System Security"),
    (0x0200_0000, "Maximum Allowed"),
    (0x1000_0000, "Generic All"),
    (0x2000_0000, "Generic Execute"),
    (0x4000_0000, "Generic Write"),
    (0x8000_0000, "Generic Read"),
];

/// Composite masks Windows itself presents as a single permission in the
/// security tab and in `icacls` output. Matched exactly: a mask that is one bit
/// away from `FILE_ALL_ACCESS` is NOT "Full Control" and must be spelled out.
const COMPOSITE_MASKS: &[(u32, &str)] = &[
    (0x001F_01FF, "Full Control"),
    (0x0013_01BF, "Modify"),
    (0x0012_00A9, "Read & Execute"),
    (0x0012_0089, "Read"),
    (0x0012_0116, "Write"),
    (0x1000_0000, "Full Control (generic)"),
];

/// Resolve a SID to a friendly account/group name, or `None` when it cannot be
/// named from the SID alone.
///
/// An examiner reading a `None` learns "this is a local or domain principal
/// whose name is not derivable from `$Secure`" — the raw SID is still shown and
/// remains the authoritative identifier. Returning a name here that does not
/// belong to the SID would misattribute file ownership, so only the fixed
/// tables above and reserved RIDs produce one.
pub fn sid_friendly_name(sid: &Sid) -> Option<String> {
    let text = sid.to_string();
    if let Some((_, name)) = WELL_KNOWN_SIDS.iter().find(|(s, _)| *s == text) {
        return Some((*name).to_string());
    }

    // Domain / machine SIDs: S-1-5-21-<32-bit x3>-<RID>. The domain triplet is
    // installation-specific, so resolution is by the trailing RID only.
    let subs = &sid.sub_authorities;
    if sid.authority == NT_AUTHORITY
        && subs.first() == Some(&SECURITY_NT_NON_UNIQUE)
        && subs.len() >= 2
    {
        let rid = *subs.last()?;
        if rid < FIRST_UNRESERVED_RID {
            if let Some((_, name)) = WELL_KNOWN_RIDS.iter().find(|(r, _)| *r == rid) {
                return Some(format!("{name} (RID {rid})"));
            }
        }
        return None;
    }

    // BUILTIN aliases not covered by the exact table stay unnamed rather than
    // being reported as a generic "BUILTIN group".
    if sid.authority == NT_AUTHORITY && subs.first() == Some(&SECURITY_BUILTIN_DOMAIN) {
        return None;
    }

    None
}

/// Name the integrity level a `SYSTEM_MANDATORY_LABEL` ACE asserts, given the
/// trustee SID.
///
/// Returns `None` for any SID outside authority 16 or with an unrecognised
/// level value: an unknown label must read as unknown, never as "Medium".
pub fn integrity_level_from_sid(sid: &Sid) -> Option<&'static str> {
    if sid.authority != MANDATORY_LABEL_AUTHORITY || sid.sub_authorities.len() != 1 {
        return None;
    }
    let rid = sid.sub_authorities[0];
    INTEGRITY_LEVELS
        .iter()
        .find(|(r, _)| *r == rid)
        .map(|(_, name)| *name)
}

/// Name an ACE type, or `None` for a value not defined by `[MS-DTYP]`.
///
/// The numeric type is always kept beside this, so an unnamed type is still
/// fully visible to the examiner.
pub fn ace_type_name(ace_type: u8) -> Option<&'static str> {
    ACE_TYPES
        .iter()
        .find(|(t, _)| *t == ace_type)
        .map(|(_, name)| *name)
}

/// True when the ACE grants access (as opposed to denying, auditing or
/// labelling). Used only for the readable summary; the raw type is what a
/// downstream detection should reason over.
pub fn ace_type_is_allow(ace_type: u8) -> bool {
    matches!(ace_type, 0x00 | 0x05 | 0x09 | 0x0B)
}

/// True when the ACE denies access.
pub fn ace_type_is_deny(ace_type: u8) -> bool {
    matches!(ace_type, 0x01 | 0x06 | 0x0A | 0x0C)
}

/// What an ACE does, as a stable machine-readable token for the UI and for
/// later detections: `allow`, `deny`, `audit`, `alarm`, `mandatory_label`,
/// `resource_attribute`, `scoped_policy`, `process_trust_label`,
/// `access_filter`, or `unknown`.
///
/// `unknown` is deliberate: an ACE type this parser does not model must not be
/// shown as "allow", which would understate or overstate who had access.
pub fn ace_effect(ace_type: u8) -> &'static str {
    match ace_type {
        0x00 | 0x05 | 0x09 | 0x0B => "allow",
        0x01 | 0x06 | 0x0A | 0x0C => "deny",
        0x02 | 0x07 | 0x0D | 0x0F => "audit",
        0x03 | 0x08 | 0x0E | 0x10 => "alarm",
        0x11 => "mandatory_label",
        0x12 => "resource_attribute",
        0x13 => "scoped_policy",
        0x14 => "process_trust_label",
        0x15 => "access_filter",
        _ => "unknown",
    }
}

/// Decode the set ACE flag bits into names. Bits with no name are omitted here
/// but remain in the raw `flags` value stored on the record.
pub fn ace_flag_names(flags: u8) -> Vec<&'static str> {
    ACE_FLAGS
        .iter()
        .filter(|(bit, _)| flags & *bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Decode the set security-descriptor control bits into names.
pub fn control_flag_names(control: u16) -> Vec<&'static str> {
    CONTROL_FLAGS
        .iter()
        .filter(|(bit, _)| control & *bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Decode the set `ACCESS_MASK` bits into file-object right names.
pub fn access_right_names(kind: ObjectKind, mask: u32) -> Vec<&'static str> {
    let tables: [BitNames; 2] = match kind {
        ObjectKind::File => [ACCESS_RIGHT_BITS, &[]],
        ObjectKind::RegistryKey => [REGISTRY_RIGHT_BITS, STANDARD_RIGHT_BITS],
    };
    tables
        .iter()
        .flat_map(|t| t.iter())
        .filter(|(bit, _)| mask & *bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// The mandatory-policy bits carried by a `SYSTEM_MANDATORY_LABEL` ACE.
///
/// These are **not** access rights, and the collision is exact:
/// `SYSTEM_MANDATORY_POLICY_NO_WRITE_UP` is `0x1`, and `0x1` in a file access
/// mask is `FILE_READ_DATA`. Rendering one through the other turns an integrity
/// label — present on essentially every user file on a modern Windows system —
/// into a statement about who may read the file (`HUNT-126`).
const MANDATORY_POLICY_BITS: &[(u32, &str)] = &[
    (0x0000_0001, "NO_WRITE_UP"),
    (0x0000_0002, "NO_READ_UP"),
    (0x0000_0004, "NO_EXECUTE_UP"),
];

/// Render a `SYSTEM_MANDATORY_LABEL` ACE's mask as the policy it is.
///
/// The hexadecimal is always appended and unnamed bits are reported explicitly,
/// on the same rule as [`describe_access_mask`]: the rendering is never the only
/// record of what the evidence held.
pub fn describe_mandatory_policy(mask: u32) -> String {
    let named: Vec<&str> = MANDATORY_POLICY_BITS
        .iter()
        .filter(|(bit, _)| mask & *bit != 0)
        .map(|(_, name)| *name)
        .collect();
    let covered = MANDATORY_POLICY_BITS
        .iter()
        .fold(0u32, |acc, (bit, _)| acc | *bit);
    let residual = mask & !covered;
    match (named.is_empty(), residual) {
        (true, _) => format!("mandatory policy 0x{mask:08X}"),
        (false, 0) => format!("mandatory policy {} (0x{mask:08X})", named.join(", ")),
        (false, r) => format!(
            "mandatory policy {} + unnamed bits 0x{r:08X} (0x{mask:08X})",
            named.join(", ")
        ),
    }
}

/// Render an `ACCESS_MASK` the way an examiner reads it: the Windows composite
/// name when the mask matches one exactly, otherwise the individual rights.
///
/// The hexadecimal mask is ALWAYS appended, so the rendering is never the only
/// record of what was granted; bits this table cannot name are reported
/// explicitly as unnamed rather than dropped.
pub fn describe_access_mask(kind: ObjectKind, mask: u32) -> String {
    let (composites, bits): (BitNames, BitNames) = match kind {
        ObjectKind::File => (COMPOSITE_MASKS, ACCESS_RIGHT_BITS),
        ObjectKind::RegistryKey => (REGISTRY_COMPOSITE_MASKS, REGISTRY_RIGHT_BITS),
    };
    if let Some((_, name)) = composites.iter().find(|(m, _)| *m == mask) {
        return format!("{name} (0x{mask:08X})");
    }
    // The object-specific bits, then the standard and generic ones, which mean
    // the same on every object kind.
    let tables: [BitNames; 2] = match kind {
        // The file table already carries its own standard and generic rows, so
        // adding them again would name each twice.
        ObjectKind::File => [bits, &[]],
        ObjectKind::RegistryKey => [bits, STANDARD_RIGHT_BITS],
    };
    let names: Vec<&str> = tables
        .iter()
        .flat_map(|t| t.iter())
        .filter(|(bit, _)| mask & *bit != 0)
        .map(|(_, name)| *name)
        .collect();
    let named_bits = tables
        .iter()
        .flat_map(|t| t.iter())
        .filter(|(bit, _)| mask & *bit != 0)
        .fold(0u32, |acc, (bit, _)| acc | *bit);
    let residual = mask & !named_bits;
    if names.is_empty() {
        return format!("0x{mask:08X}");
    }
    if residual != 0 {
        return format!(
            "{} + unnamed bits 0x{residual:08X} (0x{mask:08X})",
            names.join(", ")
        );
    }
    format!("{} (0x{mask:08X})", names.join(", "))
}
