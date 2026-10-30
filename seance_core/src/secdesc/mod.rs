//! The NT security descriptor: who owns an object and who may do what to it.
//!
//! # Why this is in `seance_core`
//!
//! The same self-relative `SECURITY_DESCRIPTOR` appears in at least two places
//! in the evidence: NTFS `$Secure:$SDS`, which describes files and
//! directories, and a registry hive's `sk` cells, which describe keys. One
//! decoder serves both. Two decoders for one structure can disagree with each
//! other about who owned something, on a surface that is quoted under oath.
//!
//! Moved here from `seance_plugin_secure_sds` on 2026-09-15 for `ROADMAP` §2.5,
//! which reads a hive's `sk` cells. `$SDS` *stream* parsing — the entry
//! headers, the 256 KiB block layout, the mirror — stays in that plugin,
//! because it is NTFS's and not the descriptor's.
//!
//! # What it is
//!
//! Every decoder here is a pure function over a byte slice: no I/O, no global
//! state, no panics on hostile input. Each either returns the structure it
//! recovered or a [`SecDescError`] that NAMES what was wrong, because "this
//! object has no owner" and "this object's owner could not be decoded" are
//! different findings and must never render the same way.
//!
//! # Layout being decoded
//!
//! ```text
//! self-relative SECURITY_DESCRIPTOR
//!  ├─ header (20 bytes): revision, control, owner/group/SACL/DACL offsets
//!  ├─ owner SID, group SID
//!  └─ ACL (8-byte header + ace_count ACEs, each with its own size)
//! ```
//!
//! # The object kind is not optional
//!
//! The low 16 bits of an `ACCESS_MASK` are object-specific: `0x1` is
//! `FILE_READ_DATA` on a file and `KEY_QUERY_VALUE` on a registry key. So a
//! descriptor carries its [`wellknown::ObjectKind`] and cannot be rendered
//! without one.

pub mod wellknown;

use std::fmt;
use wellknown::{
    ace_effect, ace_type_is_allow, ace_type_is_deny, describe_access_mask,
    describe_mandatory_policy, integrity_level_from_sid, sid_friendly_name, ObjectKind,
};

/// Bytes of the fixed part of a self-relative `SECURITY_DESCRIPTOR`.
pub const DESCRIPTOR_HEADER_LEN: usize = 0x14;
/// Bytes of an ACL header (revision, size, ACE count).
pub const ACL_HEADER_LEN: usize = 8;
/// Bytes of an ACE header (type, flags, size).
pub const ACE_HEADER_LEN: usize = 4;

/// Cap on ACEs decoded from one ACL. Hitting it marks the ACL truncated.
pub const MAX_ACES_PER_ACL: usize = 4096;
/// Maximum sub-authorities in a SID (the `[MS-DTYP]` limit).
pub const MAX_SUB_AUTHORITIES: u8 = 15;

/// `SE_DACL_PRESENT`: a DACL is attached. Clear means *no* DACL, which grants
/// everyone full access — the opposite of an empty DACL.
pub const SE_DACL_PRESENT: u16 = 0x0004;
/// `SE_SACL_PRESENT`: a SACL is attached.
pub const SE_SACL_PRESENT: u16 = 0x0010;
/// `SE_DACL_PROTECTED`: inheritance from the parent directory is blocked.
pub const SE_DACL_PROTECTED: u16 = 0x1000;
/// `SE_SACL_PROTECTED`: SACL inheritance is blocked.
pub const SE_SACL_PROTECTED: u16 = 0x2000;
/// `INHERIT_ONLY_ACE`: the ACE applies to children of this object, not to it.
pub const ACE_FLAG_INHERIT_ONLY: u8 = 0x08;

/// `SE_DACL_AUTO_INHERITED`: the DACL was propagated from the parent.
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
/// `SE_SELF_RELATIVE`: owner/group/ACL fields are byte offsets rather than
/// pointers. Every descriptor stored in `$SDS` has this set.
pub const SE_SELF_RELATIVE: u16 = 0x8000;

/// ACE type of a `SYSTEM_MANDATORY_LABEL` ACE, whose trustee SID encodes the
/// file's integrity level.
pub const ACE_TYPE_MANDATORY_LABEL: u8 = 0x11;

/// Why a structure could not be decoded.
///
/// Each variant names the field and the bound that was violated so the message
/// stored on the artifact tells an examiner exactly what was wrong with the
/// evidence, rather than "parse failed".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecDescError {
    /// The descriptor is shorter than its own fixed header.
    #[error("security descriptor is {len} bytes; the fixed header needs 20")]
    DescriptorTruncated { len: usize },

    /// `revision` is not 1. No other revision has ever been defined.
    #[error("security descriptor revision {revision} is not the defined value 1")]
    UnsupportedRevision { revision: u8 },

    /// `SE_SELF_RELATIVE` is clear, so the owner/group/ACL fields are memory
    /// pointers from a live process, not offsets. Decoding them as offsets
    /// would fabricate owners and ACLs out of unrelated bytes.
    #[error(
        "security descriptor control 0x{control:04X} lacks SE_SELF_RELATIVE; \
             its owner/group/ACL fields are pointers, not offsets, and cannot be followed"
    )]
    NotSelfRelative { control: u16 },

    /// A field's offset points outside the descriptor.
    #[error("{field} offset {offset} lies outside the {len}-byte security descriptor")]
    OffsetOutOfRange {
        field: &'static str,
        offset: u32,
        len: usize,
    },

    /// A SID's declared length runs past the end of the buffer.
    #[error("SID at offset {at} needs {need} bytes but only {available} remain")]
    SidTruncated {
        at: usize,
        need: usize,
        available: usize,
    },

    /// A SID's revision byte is not 1.
    #[error("SID at offset {at} has revision {revision}, not the defined value 1")]
    SidRevision { at: usize, revision: u8 },

    /// A SID claims more sub-authorities than `[MS-DTYP]` allows.
    #[error("SID at offset {at} claims {count} sub-authorities; the maximum is 15")]
    SidSubAuthorityCount { at: usize, count: u8 },

    /// An ACL header does not fit in the descriptor.
    #[error("ACL at offset {at} needs an 8-byte header but only {available} bytes remain")]
    AclTruncated { at: usize, available: usize },

    /// An ACL declares a size smaller than its own header.
    #[error(
        "ACL at offset {at} declares a size of {acl_size} bytes, smaller than its 8-byte header"
    )]
    AclSizeInvalid { at: usize, acl_size: u16 },

    /// An SDS entry declares more bytes than the stream holds.
    #[error(
        "SDS entry at stream offset {offset} declares {entry_size} bytes but only \
             {available} remain in the stream; the descriptor is not present to read"
    )]
    EntryPastEndOfStream {
        offset: u64,
        entry_size: u32,
        available: usize,
    },
}

/// A Windows security identifier.
///
/// The string form (`S-1-5-21-…`) is the authoritative identity of a principal;
/// friendly names are decoration that may legitimately be absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    /// SID revision; always 1 in practice.
    pub revision: u8,
    /// 48-bit identifier authority, stored big-endian on disk.
    pub authority: u64,
    /// Relative identifiers, in order. The last one is the RID.
    pub sub_authorities: Vec<u32>,
}

impl fmt::Display for Sid {
    /// Render the standard string form: `S-<revision>-<authority>-<sub>…`.
    ///
    /// The authority prints as decimal below 2^32 (every real-world case) and
    /// as hexadecimal above it, matching `ConvertSidToStringSid`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-", self.revision)?;
        if self.authority < u64::from(u32::MAX) + 1 {
            write!(f, "{}", self.authority)?;
        } else {
            write!(f, "0x{:012x}", self.authority)?;
        }
        for sub in &self.sub_authorities {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

impl Sid {
    /// Friendly name for a well-known SID, or `None` when the principal cannot
    /// be named from the SID alone (a local or domain account).
    pub fn friendly_name(&self) -> Option<String> {
        sid_friendly_name(self)
    }
}

/// One access control entry.
///
/// `access_mask` and `sid` are optional because a malformed or unmodelled ACE
/// body must yield "not decoded" (with `body_error` saying why), never a
/// zero mask or a trustee read from the wrong offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// Raw ACE type byte (0x00 allow, 0x01 deny, 0x02 audit, 0x11 label, …).
    pub ace_type: u8,
    /// Raw ACE flag byte (inheritance, audit success/failure).
    pub flags: u8,
    /// Declared size of the ACE in bytes; the walk always advances by this.
    pub size: u16,
    /// The `ACCESS_MASK`, when the body was long enough to hold it.
    pub access_mask: Option<u32>,
    /// The trustee this ACE applies to.
    pub sid: Option<Sid>,
    /// `object_flags` of an object ACE, which decides whether the two GUIDs
    /// precede the trustee SID.
    pub object_flags: Option<u32>,
    /// Why the mask or trustee is absent. `None` together with a present `sid`
    /// means a clean decode.
    pub body_error: Option<String>,
}

impl Ace {
    /// True when this ACE grants (rather than denies, audits or labels).
    pub fn is_allow(&self) -> bool {
        ace_type_is_allow(self.ace_type)
    }

    /// True when this ACE denies access.
    pub fn is_deny(&self) -> bool {
        ace_type_is_deny(self.ace_type)
    }

    /// True when this ACE is a `SYSTEM_MANDATORY_LABEL` — an integrity level,
    /// not a grant or a denial, whose mask is a policy rather than a set of
    /// access rights.
    pub fn is_mandatory_label(&self) -> bool {
        self.ace_type == ACE_TYPE_MANDATORY_LABEL
    }

    /// Whether this ACE applies to the object that carries it.
    ///
    /// `INHERIT_ONLY_ACE` means the ACE exists to be inherited by children and
    /// grants nothing here. Presenting it among the permissions on *this*
    /// object states a permission that is not in force — and on real evidence
    /// that is not a corner case: four of the eight ACEs in the real `SAM` root
    /// descriptor carry `CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE`, so the
    /// un-marked summary overstated the ACL of the most security-relevant key
    /// in Windows (`HUNT-126`).
    ///
    /// `INHERITED_ACE` (`0x10`) is a different thing and does **not** withhold
    /// the ACE: it records that this ACE arrived from the parent, and it is in
    /// force here all the same.
    pub fn applies_to_this_object(&self) -> bool {
        self.flags & ACE_FLAG_INHERIT_ONLY == 0
    }

    /// Trustee rendered for display: friendly name when the SID is well known,
    /// otherwise the raw SID, otherwise an explicit "not decoded" marker.
    pub fn trustee_label(&self) -> String {
        match &self.sid {
            Some(sid) => sid.friendly_name().unwrap_or_else(|| sid.to_string()),
            None => match &self.body_error {
                Some(e) => format!("trustee not decoded ({e})"),
                None => "trustee not decoded".to_string(),
            },
        }
    }
}

/// A decoded access control list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    /// ACL revision: 2 for file ACLs, 4 when object ACEs are present.
    pub revision: u8,
    /// Total ACL size declared in the header.
    pub size: u16,
    /// ACE count declared in the header. Compare against `aces.len()`.
    pub declared_ace_count: u16,
    /// The ACEs actually decoded, in order.
    pub aces: Vec<Ace>,
    /// True when fewer ACEs were decoded than declared, or a cap was hit.
    pub truncated: bool,
    /// What stopped the walk, when `truncated` is set.
    pub truncation_reason: Option<String>,
}

/// Whether an ACL is attached to a descriptor, and if so whether it decoded.
///
/// The distinction between these four states is the whole point: an ABSENT or
/// NULL DACL means *everyone has full access*, while a PRESENT DACL holding
/// zero ACEs means *nobody has any access*. Collapsing them into
/// `Option<Acl>`, as most parsers do, inverts the finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclPresence {
    /// The `SE_*_ACL_PRESENT` control bit is clear: no ACL exists. For a DACL
    /// this is unrestricted access for every principal.
    Absent,
    /// The present bit is set but the offset is zero: a NULL ACL. For a DACL
    /// this is also unrestricted access.
    Null,
    /// An ACL is attached and was decoded.
    Present(Acl),
    /// An ACL is attached but its bytes could not be decoded. Access here is
    /// UNKNOWN — it must not be reported as unrestricted or as denied.
    Unreadable(String),
}

impl AclPresence {
    /// The decoded ACL, if there is one.
    pub fn acl(&self) -> Option<&Acl> {
        match self {
            AclPresence::Present(acl) => Some(acl),
            _ => None,
        }
    }

    /// Stable state name stored on the artifact (`present`, `absent`, `null`,
    /// `unreadable`) so the UI can tell the four apart without re-deriving them.
    pub fn state(&self) -> &'static str {
        match self {
            AclPresence::Absent => "absent",
            AclPresence::Null => "null",
            AclPresence::Present(_) => "present",
            AclPresence::Unreadable(_) => "unreadable",
        }
    }

    /// True when this ACL, as a DACL, imposes no restriction at all (absent or
    /// NULL): every principal gets full access.
    pub fn grants_everyone_full_access(&self) -> bool {
        matches!(self, AclPresence::Absent | AclPresence::Null)
    }
}

/// A decoded self-relative `SECURITY_DESCRIPTOR`.
///
/// Sub-structures fail independently: a corrupt DACL does not discard a good
/// owner. Any such failure sets `partial`, and the per-field error strings say
/// which part is missing and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor {
    /// Descriptor revision (1).
    pub revision: u8,
    /// Control bitfield.
    pub control: u16,
    /// Owner SID, when the descriptor records one and it decoded.
    pub owner: Option<Sid>,
    /// Why the owner is absent, when it should have been present.
    pub owner_error: Option<String>,
    /// Primary group SID.
    pub group: Option<Sid>,
    /// Why the group is absent, when it should have been present.
    pub group_error: Option<String>,
    /// Discretionary ACL state: who may access the object.
    pub dacl: AclPresence,
    /// System ACL state: what is audited, plus the mandatory label.
    pub sacl: AclPresence,
    /// True when any sub-structure failed to decode or was truncated. A partial
    /// descriptor must never be presented as a complete permission picture.
    pub partial: bool,
    /// Which kind of object this descriptor was found on.
    ///
    /// Carried on the descriptor rather than passed to each renderer, so that a
    /// descriptor cannot be rendered without it. The low 16 bits of an access
    /// mask are object-specific — `0x1` is `FILE_READ_DATA` on a file and
    /// `KEY_QUERY_VALUE` on a registry key — so a renderer that does not know
    /// which it has would name those bits by guessing (§2.5).
    pub object_kind: ObjectKind,
}

impl SecurityDescriptor {
    /// Integrity level asserted by a `SYSTEM_MANDATORY_LABEL` ACE in the SACL.
    ///
    /// `None` means no label ACE was found — which is normal, and is NOT the
    /// same as "Medium"; Windows only writes the label when it differs from the
    /// default, so a missing label must stay missing.
    pub fn integrity_level(&self) -> Option<&'static str> {
        let acl = self.sacl.acl()?;
        acl.aces
            .iter()
            .filter(|a| a.ace_type == ACE_TYPE_MANDATORY_LABEL)
            .find_map(|a| a.sid.as_ref().and_then(integrity_level_from_sid))
    }

    /// True when the DACL is protected from inheritance (`SE_DACL_PROTECTED`).
    /// Broken inheritance on a user data file is a common tampering signal.
    pub fn dacl_protected(&self) -> bool {
        self.control & SE_DACL_PROTECTED != 0
    }

    /// True when there is effectively no DACL, so every principal has full
    /// access to the object.
    pub fn no_dacl_full_access(&self) -> bool {
        self.dacl.grants_everyone_full_access()
    }

    /// Owner rendered for display, or `None` when the descriptor records none.
    pub fn owner_label(&self) -> Option<String> {
        self.owner
            .as_ref()
            .map(|s| s.friendly_name().unwrap_or_else(|| s.to_string()))
    }

    /// One-line readable permission summary, e.g.
    /// `Owner: Administrators; DACL: Local System = Full Control, Users = Read & Execute`.
    ///
    /// The summary is a reading aid only. It always states the DACL's state in
    /// words, so "no DACL (everyone has full access)" can never be mistaken for
    /// "empty DACL (no access for anyone)", and it says when it truncated the
    /// ACE list rather than quietly showing a prefix.
    pub fn permission_summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        parts.push(match (&self.owner, &self.owner_error) {
            (Some(sid), _) => format!(
                "Owner: {}",
                sid.friendly_name().unwrap_or_else(|| sid.to_string())
            ),
            (None, Some(e)) => format!("Owner: not decoded ({e})"),
            (None, None) => "Owner: not recorded".to_string(),
        });

        if let Some(group) = &self.group {
            parts.push(format!(
                "Group: {}",
                group.friendly_name().unwrap_or_else(|| group.to_string())
            ));
        } else if let Some(e) = &self.group_error {
            parts.push(format!("Group: not decoded ({e})"));
        }

        parts.push(summarize_acl(AclRole::Dacl, &self.dacl, self.object_kind));
        if !matches!(self.sacl, AclPresence::Absent) {
            parts.push(summarize_acl(AclRole::Sacl, &self.sacl, self.object_kind));
        }
        if let Some(level) = self.integrity_level() {
            parts.push(format!("Integrity: {level}"));
        }
        parts.join("; ")
    }
}

/// Cap on ACEs named individually in a permission summary. The full list always
/// remains on the record; this only bounds the one-line rendering.
const SUMMARY_ACE_LIMIT: usize = 12;

/// Which list of a descriptor is being summarised. A DACL says who may do what;
/// a SACL says what is audited and grants or withholds nothing, so the two must
/// not share sentences about "access".
#[derive(Clone, Copy, PartialEq, Eq)]
enum AclRole {
    Dacl,
    Sacl,
}

impl AclRole {
    fn label(self) -> &'static str {
        match self {
            AclRole::Dacl => "DACL",
            AclRole::Sacl => "SACL",
        }
    }
}

/// The verb that opens an ACE's rendering, from the shared ACE classification.
/// An allow reads as the bare grant; every other effect is named, and a type
/// this parser does not model says so rather than posing as an audit.
fn ace_verb(ace_type: u8) -> String {
    match ace_effect(ace_type) {
        "allow" => String::new(),
        "deny" => "DENY ".to_string(),
        "audit" => "AUDIT ".to_string(),
        "alarm" => "ALARM ".to_string(),
        "mandatory_label" => "LABEL ".to_string(),
        _ => format!("UNMODELLED(0x{ace_type:02X}) "),
    }
}

/// Render one ACL for [`SecurityDescriptor::permission_summary`].
fn summarize_acl(role: AclRole, presence: &AclPresence, kind: ObjectKind) -> String {
    let label = role.label();
    match (presence, role) {
        (AclPresence::Absent, AclRole::Dacl) => {
            format!("{label}: none present (everyone has full access)")
        }
        (AclPresence::Absent, AclRole::Sacl) => format!("{label}: none present (nothing audited)"),
        (AclPresence::Null, AclRole::Dacl) => format!("{label}: NULL (everyone has full access)"),
        (AclPresence::Null, AclRole::Sacl) => format!("{label}: NULL (nothing audited)"),
        (AclPresence::Unreadable(e), AclRole::Dacl) => {
            format!("{label}: unreadable ({e}) - access unknown")
        }
        (AclPresence::Unreadable(e), AclRole::Sacl) => {
            format!("{label}: unreadable ({e}) - audit policy unknown")
        }
        (AclPresence::Present(acl), AclRole::Dacl) if acl.aces.is_empty() && !acl.truncated => {
            format!("{label}: empty (no access granted to anyone)")
        }
        (AclPresence::Present(acl), AclRole::Sacl) if acl.aces.is_empty() && !acl.truncated => {
            format!("{label}: empty (nothing audited)")
        }
        (AclPresence::Present(acl), _) => {
            let mut items: Vec<String> = acl
                .aces
                .iter()
                .take(SUMMARY_ACE_LIMIT)
                .map(|ace| {
                    let verb = ace_verb(ace.ace_type);
                    // A mandatory label's mask is a policy, and the bits
                    // collide exactly with file rights, so the two renderings
                    // must not share a path (HUNT-126).
                    let mask = match (ace.access_mask, ace.is_mandatory_label()) {
                        (Some(m), true) => describe_mandatory_policy(m),
                        (Some(m), false) => describe_access_mask(kind, m),
                        (None, _) => "mask not decoded".to_string(),
                    };
                    // An inherit-only ACE grants nothing on this object, and a
                    // summary of what is granted here must not list it as
                    // though it did.
                    let scope = if ace.applies_to_this_object() {
                        ""
                    } else {
                        match kind {
                            ObjectKind::RegistryKey => {
                                " [inherit-only: applies to child keys, not to this object]"
                            }
                            ObjectKind::File => {
                                " [inherit-only: applies to child files and folders, not to this object]"
                            }
                        }
                    };
                    format!("{verb}{} = {mask}{scope}", ace.trustee_label())
                })
                .collect();
            if acl.aces.len() > SUMMARY_ACE_LIMIT {
                items.push(format!("+{} more", acl.aces.len() - SUMMARY_ACE_LIMIT));
            }
            let mut out = format!("{label}: {}", items.join(", "));
            if acl.truncated {
                let reason = acl.truncation_reason.as_deref().unwrap_or("truncated");
                out.push_str(&format!(" [INCOMPLETE: {reason}]"));
            }
            out
        }
    }
}

/// Read a little-endian `u16` at `at`. The caller must have established that
/// `at + 2 <= buf.len()`; every call site does so with an explicit bounds check
/// that returns a named error, so there is no silent zero fallback anywhere.
pub(crate) fn le_u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([buf[at], buf[at + 1]])
}

/// Read a little-endian `u32` at `at`, under the same precondition as
/// [`le_u16_at`].
pub(crate) fn le_u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Read a little-endian `u32` at `at`, or `None` when it does not fit.
fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    buf.get(at..end)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decode a SID at `at`, returning it with the number of bytes it occupies.
///
/// The identifier authority is the one big-endian field in the whole format. A
/// SID whose declared sub-authority count runs past the buffer is rejected
/// outright: reading a short SID would silently produce a DIFFERENT principal.
pub fn parse_sid(buf: &[u8], at: usize) -> Result<(Sid, usize), SecDescError> {
    // Bytes left from `at`. saturating_sub makes an out-of-range offset read as
    // "nothing available" instead of wrapping into a huge length.
    let available = buf.len().saturating_sub(at);
    if available < 8 {
        return Err(SecDescError::SidTruncated {
            at,
            need: 8,
            available,
        });
    }
    let revision = buf[at];
    if revision != 1 {
        return Err(SecDescError::SidRevision { at, revision });
    }
    let count = buf[at + 1];
    if count > MAX_SUB_AUTHORITIES {
        return Err(SecDescError::SidSubAuthorityCount { at, count });
    }
    // 48-bit big-endian identifier authority.
    let mut authority: u64 = 0;
    for b in &buf[at + 2..at + 8] {
        authority = (authority << 8) | u64::from(*b);
    }
    // count is capped at 15 above, so this is at most 68 and cannot overflow.
    let need = 8 + 4 * usize::from(count);
    if available < need {
        return Err(SecDescError::SidTruncated {
            at,
            need,
            available,
        });
    }
    let mut sub_authorities = Vec::with_capacity(usize::from(count));
    for i in 0..usize::from(count) {
        let off = at + 8 + i * 4;
        sub_authorities.push(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]));
    }
    Ok((
        Sid {
            revision,
            authority,
            sub_authorities,
        },
        need,
    ))
}

/// ACE types whose body carries `object_flags` and up to two GUIDs before the
/// trustee SID ([MS-DTYP] §2.4.4.3 and friends).
fn is_object_ace(ace_type: u8) -> bool {
    matches!(
        ace_type,
        0x05 | 0x06 | 0x07 | 0x08 | 0x0B | 0x0C | 0x0F | 0x10
    )
}

/// ACE types whose body is `access_mask` followed directly by the trustee SID.
fn is_basic_ace(ace_type: u8) -> bool {
    matches!(
        ace_type,
        0x00 | 0x01 | 0x02 | 0x03 | 0x09 | 0x0A | 0x0D | 0x0E | 0x11 | 0x12 | 0x13 | 0x14 | 0x15
    )
}

/// Decode one ACE occupying `buf[at .. at + size]`.
///
/// Returns `None` only when the 4-byte ACE header itself lies outside `buf` —
/// there is then nothing to report, not even a type. Otherwise it always
/// returns an ACE, because the ACL walk must be able to step over an entry it
/// cannot understand. What it will NOT do is guess: an unmodelled body (a
/// compound ACE, or a type `[MS-DTYP]` does not define) yields `sid: None` with
/// a `body_error` naming the type, so an examiner sees "trustee not decoded"
/// instead of a SID read from the wrong offset.
pub fn parse_ace(buf: &[u8], at: usize, size: u16) -> Option<Ace> {
    if at.saturating_add(ACE_HEADER_LEN) > buf.len() {
        return None;
    }
    let ace_type = buf[at];
    let flags = buf[at + 1];
    let end = at.saturating_add(usize::from(size)).min(buf.len());

    let mut ace = Ace {
        ace_type,
        flags,
        size,
        access_mask: None,
        sid: None,
        object_flags: None,
        body_error: None,
    };

    let body = &buf[at..end];
    if body.len() < ACE_HEADER_LEN + 4 {
        ace.body_error = Some(format!(
            "ACE body is {} bytes; an access mask needs 8",
            body.len()
        ));
        return Some(ace);
    }
    // The length check above guarantees the mask is present.
    ace.access_mask = Some(le_u32_at(body, ACE_HEADER_LEN));

    let sid_offset = if is_basic_ace(ace_type) {
        ACE_HEADER_LEN + 4
    } else if is_object_ace(ace_type) {
        let Some(object_flags) = le_u32(body, ACE_HEADER_LEN + 4) else {
            ace.body_error = Some("object ACE is too short to hold its object flags".to_string());
            return Some(ace);
        };
        ace.object_flags = Some(object_flags);
        // Each present GUID pushes the trustee SID 16 bytes further along.
        let mut off = ACE_HEADER_LEN + 8;
        if object_flags & 0x1 != 0 {
            off += 16;
        }
        if object_flags & 0x2 != 0 {
            off += 16;
        }
        off
    } else {
        ace.body_error = Some(format!(
            "ACE type 0x{ace_type:02X} has a body layout this parser does not model; \
             its trustee was not decoded"
        ));
        return Some(ace);
    };

    match parse_sid(body, sid_offset) {
        Ok((sid, _)) => ace.sid = Some(sid),
        Err(e) => ace.body_error = Some(e.to_string()),
    }
    Some(ace)
}

/// Decode the ACL at `at` within `buf`.
///
/// The walk advances by each ACE's own declared `ace_size`, never by a size
/// computed from the body, so an unknown or object ACE cannot desynchronise the
/// list and turn the following bytes into a fabricated ACE. Any shortfall
/// against the declared ACE count sets `truncated` with a reason.
pub fn parse_acl(buf: &[u8], at: usize) -> Result<Acl, SecDescError> {
    let available = buf.len().saturating_sub(at);
    if available < ACL_HEADER_LEN {
        return Err(SecDescError::AclTruncated { at, available });
    }
    // available >= ACL_HEADER_LEN, so bytes at+2..at+6 are present.
    let revision = buf[at];
    let size = le_u16_at(buf, at + 2);
    let declared_ace_count = le_u16_at(buf, at + 4);
    if usize::from(size) < ACL_HEADER_LEN {
        return Err(SecDescError::AclSizeInvalid { at, acl_size: size });
    }

    let mut truncated = false;
    let mut truncation_reason: Option<String> = None;
    // The ACL may claim more bytes than the descriptor holds; clamp to what is
    // actually there and say so, rather than reading past the descriptor.
    let declared_end = at.saturating_add(usize::from(size));
    let end = if declared_end > buf.len() {
        truncated = true;
        truncation_reason = Some(format!(
            "ACL declares {size} bytes at offset {at} but only {} remain in the descriptor",
            buf.len().saturating_sub(at)
        ));
        buf.len()
    } else {
        declared_end
    };

    let mut aces: Vec<Ace> = Vec::new();
    let mut cursor = at + ACL_HEADER_LEN;
    while aces.len() < usize::from(declared_ace_count) {
        if aces.len() >= MAX_ACES_PER_ACL {
            truncated = true;
            truncation_reason = Some(format!(
                "stopped at the {MAX_ACES_PER_ACL}-ACE cap; the ACL declares {declared_ace_count}"
            ));
            break;
        }
        if cursor.saturating_add(ACE_HEADER_LEN) > end {
            truncated = true;
            truncation_reason.get_or_insert(format!(
                "ACL declares {declared_ace_count} ACEs but the bytes ran out after {}",
                aces.len()
            ));
            break;
        }
        // The check above guarantees cursor+4 <= end <= buf.len().
        let ace_size = le_u16_at(buf, cursor + 2);
        if usize::from(ace_size) < ACE_HEADER_LEN
            || cursor.saturating_add(usize::from(ace_size)) > end
        {
            truncated = true;
            truncation_reason.get_or_insert(format!(
                "ACE {} at offset {cursor} declares an unusable size of {ace_size} bytes; \
                 the rest of the ACL cannot be located",
                aces.len()
            ));
            break;
        }
        match parse_ace(buf, cursor, ace_size) {
            Some(ace) => aces.push(ace),
            None => {
                truncated = true;
                truncation_reason.get_or_insert(format!(
                    "ACE {} at offset {cursor} lies outside the descriptor",
                    aces.len()
                ));
                break;
            }
        }
        cursor += usize::from(ace_size);
    }

    Ok(Acl {
        revision,
        size,
        declared_ace_count,
        aces,
        truncated,
        truncation_reason,
    })
}

/// Decode an optional SID field (owner or group) given its offset.
///
/// Returns `(None, None)` when the descriptor genuinely records no such SID
/// (offset 0), and `(None, Some(reason))` when one was recorded but could not
/// be read.
fn parse_optional_sid(
    buf: &[u8],
    offset: u32,
    field: &'static str,
) -> (Option<Sid>, Option<String>) {
    if offset == 0 {
        return (None, None);
    }
    let at = offset as usize;
    if at >= buf.len() {
        return (
            None,
            Some(
                SecDescError::OffsetOutOfRange {
                    field,
                    offset,
                    len: buf.len(),
                }
                .to_string(),
            ),
        );
    }
    match parse_sid(buf, at) {
        Ok((sid, _)) => (Some(sid), None),
        Err(e) => (None, Some(e.to_string())),
    }
}

/// Decode an ACL field given its presence bit and offset.
fn parse_acl_field(buf: &[u8], present: bool, offset: u32, field: &'static str) -> AclPresence {
    if !present {
        return AclPresence::Absent;
    }
    if offset == 0 {
        return AclPresence::Null;
    }
    let at = offset as usize;
    if at >= buf.len() {
        return AclPresence::Unreadable(
            SecDescError::OffsetOutOfRange {
                field,
                offset,
                len: buf.len(),
            }
            .to_string(),
        );
    }
    match parse_acl(buf, at) {
        Ok(acl) => AclPresence::Present(acl),
        Err(e) => AclPresence::Unreadable(e.to_string()),
    }
}

/// Decode a self-relative `SECURITY_DESCRIPTOR` from `buf`.
///
/// Rejects outright only what cannot be interpreted at all: a short buffer, an
/// unknown revision, or a descriptor that is not self-relative. Everything
/// beyond that degrades field by field, because a file's owner is still
/// evidence when its DACL is corrupt.
pub fn parse_security_descriptor(buf: &[u8]) -> Result<SecurityDescriptor, SecDescError> {
    // `$Secure:$SDS` describes files and directories, and this crate is that
    // stream's reader, so the kind is not in doubt on this path. A registry
    // key's descriptor — the same NT structure, out of a hive's `sk` cell —
    // comes through `parse_security_descriptor_on`.
    parse_security_descriptor_on(ObjectKind::File, buf)
}

/// Decode a self-relative security descriptor found on `kind`.
///
/// The kind is required rather than defaulted: the object-specific low bits of
/// every ACE's access mask mean different things on a file and on a registry
/// key, and a default would render one as the other silently. That is the shape
/// of `HUNT-126`, where a mandatory-policy mask and a file access mask shared a
/// code path because their bits collide.
pub fn parse_security_descriptor_on(
    kind: ObjectKind,
    buf: &[u8],
) -> Result<SecurityDescriptor, SecDescError> {
    if buf.len() < DESCRIPTOR_HEADER_LEN {
        return Err(SecDescError::DescriptorTruncated { len: buf.len() });
    }
    let revision = buf[0];
    if revision != 1 {
        return Err(SecDescError::UnsupportedRevision { revision });
    }
    // The length check above guarantees the 20-byte header is present.
    let control = le_u16_at(buf, 2);
    if control & SE_SELF_RELATIVE == 0 {
        return Err(SecDescError::NotSelfRelative { control });
    }
    let owner_offset = le_u32_at(buf, 4);
    let group_offset = le_u32_at(buf, 8);
    let sacl_offset = le_u32_at(buf, 12);
    let dacl_offset = le_u32_at(buf, 16);

    let (owner, owner_error) = parse_optional_sid(buf, owner_offset, "owner SID");
    let (group, group_error) = parse_optional_sid(buf, group_offset, "group SID");
    let dacl = parse_acl_field(buf, control & SE_DACL_PRESENT != 0, dacl_offset, "DACL");
    let sacl = parse_acl_field(buf, control & SE_SACL_PRESENT != 0, sacl_offset, "SACL");

    let acl_incomplete = |p: &AclPresence| match p {
        AclPresence::Unreadable(_) => true,
        AclPresence::Present(acl) => {
            acl.truncated || acl.aces.iter().any(|a| a.body_error.is_some())
        }
        _ => false,
    };
    let partial = owner_error.is_some()
        || group_error.is_some()
        || acl_incomplete(&dacl)
        || acl_incomplete(&sacl);

    Ok(SecurityDescriptor {
        object_kind: kind,
        revision,
        control,
        owner,
        owner_error,
        group,
        group_error,
        dacl,
        sacl,
        partial,
    })
}

#[cfg(test)]
mod summary_tests {
    use super::*;

    fn ace(ace_type: u8, flags: u8) -> Ace {
        Ace {
            ace_type,
            flags,
            size: 8,
            access_mask: Some(0x1),
            sid: None,
            object_flags: None,
            body_error: None,
        }
    }

    fn acl(aces: Vec<Ace>) -> AclPresence {
        AclPresence::Present(Acl {
            revision: 2,
            size: 8,
            declared_ace_count: aces.len() as u16,
            aces,
            truncated: false,
            truncation_reason: None,
        })
    }

    fn descriptor(kind: ObjectKind, dacl: AclPresence, sacl: AclPresence) -> SecurityDescriptor {
        SecurityDescriptor {
            revision: 1,
            control: 0,
            owner: None,
            owner_error: None,
            group: None,
            group_error: None,
            dacl,
            sacl,
            partial: false,
            object_kind: kind,
        }
    }

    #[test]
    fn unclassified_ace_types_are_not_labelled_audit() {
        let d = descriptor(
            ObjectKind::File,
            acl(vec![ace(0x04, 0), ace(0x11, 0), ace(0x20, 0), ace(0x02, 0)]),
            AclPresence::Absent,
        );
        let s = d.permission_summary();
        assert!(s.contains("UNMODELLED(0x04) "), "{s}");
        assert!(s.contains("UNMODELLED(0x20) "), "{s}");
        assert!(s.contains("LABEL "), "{s}");
        assert_eq!(
            s.matches("AUDIT ").count(),
            1,
            "only the real audit ACE: {s}"
        );
    }

    #[test]
    fn a_sacl_is_never_described_in_terms_of_access() {
        for (sacl, expect) in [
            (AclPresence::Null, "SACL: NULL (nothing audited)"),
            (acl(vec![]), "SACL: empty (nothing audited)"),
            (
                AclPresence::Unreadable("bad".into()),
                "SACL: unreadable (bad) - audit policy unknown",
            ),
        ] {
            let d = descriptor(ObjectKind::File, AclPresence::Null, sacl);
            let s = d.permission_summary();
            assert!(s.contains(expect), "{s}");
            let sacl_part = &s[s.find("SACL").unwrap()..];
            assert!(!sacl_part.contains("access"), "{s}");
        }
    }

    #[test]
    fn inherit_only_wording_follows_the_object_kind() {
        let inherit_only = acl(vec![ace(0x00, ACE_FLAG_INHERIT_ONLY)]);
        let file = descriptor(ObjectKind::File, inherit_only.clone(), AclPresence::Absent);
        let s = file.permission_summary();
        assert!(s.contains("inherit-only"), "{s}");
        assert!(!s.contains("keys"), "{s}");
        let key = descriptor(ObjectKind::RegistryKey, inherit_only, AclPresence::Absent);
        assert!(key.permission_summary().contains("child keys"));
    }
}
