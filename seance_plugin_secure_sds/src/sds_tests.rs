//! Unit tests for the `$SDS` decoders, built on hand-laid byte fixtures.
//!
//! Every fixture is written from the on-disk layout documented in [`crate::sds`]
//! so the tests fail if the layout is misread, not merely if the code changes.
//! Failure paths are exercised as hard as success paths: the questions an
//! examiner asks of this parser are "who owned it" and "could this have been
//! tampered with", and both are answered wrongly by a decoder that guesses.

// `crate::sds` re-exports the descriptor decoder and its name tables from
// `seance_core::secdesc`, so this one import reaches both (§2.5).
use crate::sds::*;

// --- fixture builders --------------------------------------------------------

/// Encode a SID: revision 1, 48-bit big-endian authority, little-endian subs.
pub(crate) fn sid_bytes(authority: u64, subs: &[u32]) -> Vec<u8> {
    let mut out = vec![1u8, subs.len() as u8];
    out.extend_from_slice(&authority.to_be_bytes()[2..]);
    for sub in subs {
        out.extend_from_slice(&sub.to_le_bytes());
    }
    out
}

/// Encode a basic ACE (header + access mask + trailing body, usually the SID).
pub(crate) fn ace_bytes(ace_type: u8, flags: u8, mask: u32, tail: &[u8]) -> Vec<u8> {
    let size = (8 + tail.len()) as u16;
    let mut out = vec![ace_type, flags];
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&mask.to_le_bytes());
    out.extend_from_slice(tail);
    out
}

/// Encode an ACL header followed by the given ACE bodies.
pub(crate) fn acl_bytes(revision: u8, aces: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = aces.concat();
    let size = (ACL_HEADER_LEN + body.len()) as u16;
    let mut out = vec![revision, 0];
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&body);
    out
}

/// Append `data` to the descriptor body, returning the offset it landed at
/// (relative to the start of the descriptor), or 0 when there is nothing.
fn append_field(body: &mut Vec<u8>, data: Option<&[u8]>) -> u32 {
    match data {
        Some(d) => {
            let offset = (DESCRIPTOR_HEADER_LEN + body.len()) as u32;
            body.extend_from_slice(d);
            offset
        }
        None => 0,
    }
}

/// Assemble a self-relative `SECURITY_DESCRIPTOR`.
pub(crate) fn descriptor_bytes(
    control: u16,
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    sacl: Option<&[u8]>,
    dacl: Option<&[u8]>,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    let owner_off = append_field(&mut body, owner);
    let group_off = append_field(&mut body, group);
    let sacl_off = append_field(&mut body, sacl);
    let dacl_off = append_field(&mut body, dacl);

    let mut out = vec![1u8, 0u8];
    out.extend_from_slice(&control.to_le_bytes());
    out.extend_from_slice(&owner_off.to_le_bytes());
    out.extend_from_slice(&group_off.to_le_bytes());
    out.extend_from_slice(&sacl_off.to_le_bytes());
    out.extend_from_slice(&dacl_off.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Wrap a descriptor in an SDS entry header and pad to the 16-byte alignment
/// the next entry starts on.
pub(crate) fn sds_entry(hash: u32, security_id: u32, offset: u64, descriptor: &[u8]) -> Vec<u8> {
    let entry_size = (SDS_HEADER_LEN + descriptor.len()) as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&hash.to_le_bytes());
    out.extend_from_slice(&security_id.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&entry_size.to_le_bytes());
    out.extend_from_slice(descriptor);
    while out.len() % 16 != 0 {
        out.push(0);
    }
    out
}

/// The canonical descriptor used across the tests: owned by BUILTIN\\
/// Administrators, primary group Domain Users, a four-ACE DACL and a SACL
/// carrying a Medium integrity label.
pub(crate) fn canonical_descriptor() -> Vec<u8> {
    let system = sid_bytes(5, &[18]);
    let admins = sid_bytes(5, &[32, 544]);
    let users = sid_bytes(5, &[32, 545]);
    let guests = sid_bytes(5, &[32, 546]);
    let domain_users = sid_bytes(5, &[21, 1, 2, 3, 513]);
    let medium = sid_bytes(16, &[0x2000]);

    let dacl = acl_bytes(
        2,
        &[
            ace_bytes(0x00, 0x03, 0x001F_01FF, &system),
            ace_bytes(0x00, 0x03, 0x001F_01FF, &admins),
            ace_bytes(0x00, 0x13, 0x0012_00A9, &users),
            ace_bytes(0x01, 0x00, 0x0012_00A9, &guests),
        ],
    );
    let sacl = acl_bytes(2, &[ace_bytes(0x11, 0x00, 0x0000_0001, &medium)]);
    descriptor_bytes(
        SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT,
        Some(&admins),
        Some(&domain_users),
        Some(&sacl),
        Some(&dacl),
    )
}

// --- SID decoding ------------------------------------------------------------

#[test]
fn parse_sid_decodes_the_local_system_sid_to_its_string_form() {
    // 01 01 | 00 00 00 00 00 05 | 12 00 00 00  ->  S-1-5-18
    let bytes = sid_bytes(5, &[18]);
    assert_eq!(
        bytes,
        vec![1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0],
        "the fixture itself must match the documented on-disk layout"
    );
    let (sid, len) = parse_sid(&bytes, 0).expect("a well-formed SID must decode");
    assert_eq!(sid.to_string(), "S-1-5-18");
    assert_eq!(len, 12);
    assert_eq!(sid.friendly_name().as_deref(), Some("Local System"));
}

#[test]
fn parse_sid_reads_the_identifier_authority_big_endian() {
    // Authority 16 stored big-endian is 00 00 00 00 00 10; reading it
    // little-endian would yield 0x1000000000000 and lose the integrity level.
    let bytes = sid_bytes(16, &[0x2000]);
    assert_eq!(&bytes[2..8], &[0, 0, 0, 0, 0, 16]);
    let (sid, _) = parse_sid(&bytes, 0).expect("the label SID must decode");
    assert_eq!(sid.authority, 16);
    assert_eq!(sid.to_string(), "S-1-16-8192");
    assert_eq!(integrity_level_from_sid(&sid), Some("Medium"));
}

#[test]
fn parse_sid_decodes_a_builtin_group_and_names_it() {
    let bytes = sid_bytes(5, &[32, 544]);
    let (sid, len) = parse_sid(&bytes, 0).expect("BUILTIN\\Administrators must decode");
    assert_eq!(sid.to_string(), "S-1-5-32-544");
    assert_eq!(len, 16);
    assert_eq!(sid.friendly_name().as_deref(), Some("Administrators"));
}

#[test]
fn a_domain_sid_resolves_by_its_trailing_rid_and_a_user_account_stays_unnamed() {
    let group = sid_bytes(5, &[21, 111, 222, 333, 513]);
    let (sid, _) = parse_sid(&group, 0).expect("the domain group SID must decode");
    assert_eq!(sid.to_string(), "S-1-5-21-111-222-333-513");
    assert_eq!(
        sid.friendly_name().as_deref(),
        Some("Domain Users (RID 513)")
    );

    // A locally created account cannot be named from the descriptor store, and
    // guessing one would put the wrong person against a file.
    let user = sid_bytes(5, &[21, 111, 222, 333, 1013]);
    let (sid, _) = parse_sid(&user, 0).expect("the user SID must decode");
    assert_eq!(sid.to_string(), "S-1-5-21-111-222-333-1013");
    assert_eq!(sid.friendly_name(), None);
}

#[test]
fn parse_sid_rejects_a_sub_authority_count_that_runs_past_the_buffer() {
    // Claims five sub-authorities but carries one: decoding it short would
    // report a completely different principal.
    let mut bytes = sid_bytes(5, &[21]);
    bytes[1] = 5;
    let err = parse_sid(&bytes, 0).expect_err("a short SID must be rejected");
    assert!(
        matches!(err, SdsError::SidTruncated { need: 28, .. }),
        "expected a truncation naming the required length, got {err}"
    );
}

#[test]
fn parse_sid_rejects_a_revision_other_than_one_and_an_impossible_sub_authority_count() {
    let mut bad_revision = sid_bytes(5, &[18]);
    bad_revision[0] = 2;
    assert!(matches!(
        parse_sid(&bad_revision, 0),
        Err(SdsError::SidRevision { revision: 2, .. })
    ));

    let mut too_many = sid_bytes(5, &[18]);
    too_many[1] = 200;
    assert!(matches!(
        parse_sid(&too_many, 0),
        Err(SdsError::SidSubAuthorityCount { count: 200, .. })
    ));

    // An offset past the end is a truncation, not a panic.
    assert!(parse_sid(&sid_bytes(5, &[18]), 9_999).is_err());
}

// --- access masks ------------------------------------------------------------

#[test]
fn describe_access_mask_names_the_well_known_composite_masks() {
    assert_eq!(
        describe_access_mask(ObjectKind::File, 0x001F_01FF),
        "Full Control (0x001F01FF)"
    );
    assert_eq!(
        describe_access_mask(ObjectKind::File, 0x0013_01BF),
        "Modify (0x001301BF)"
    );
    assert_eq!(
        describe_access_mask(ObjectKind::File, 0x0012_00A9),
        "Read & Execute (0x001200A9)"
    );
    assert_eq!(
        describe_access_mask(ObjectKind::File, 0x0012_0089),
        "Read (0x00120089)"
    );
    assert_eq!(
        describe_access_mask(ObjectKind::File, 0x0012_0116),
        "Write (0x00120116)"
    );
}

#[test]
fn describe_access_mask_spells_out_a_mask_that_is_not_a_known_composite() {
    // One bit short of FILE_ALL_ACCESS must NOT read as "Full Control".
    let almost_full = 0x001F_01FF & !0x0000_0040;
    let text = describe_access_mask(ObjectKind::File, almost_full);
    assert!(!text.contains("Full Control"), "got {text}");
    assert!(text.contains("Read Data"), "got {text}");
    assert!(text.contains("0x001F01BF"), "got {text}");

    // A mask with no named bits still renders its raw value.
    assert_eq!(
        describe_access_mask(ObjectKind::File, 0x0000_0200),
        "0x00000200"
    );

    // Named bits plus an unnamed one: the unnamed part is reported, not hidden.
    let text = describe_access_mask(ObjectKind::File, 0x0000_0001 | 0x0000_0200);
    assert!(text.contains("unnamed bits 0x00000200"), "got {text}");
}

// --- ACE decoding ------------------------------------------------------------

#[test]
fn parse_ace_decodes_an_allowed_ace_with_its_trustee_and_flags() {
    let sid = sid_bytes(5, &[18]);
    let bytes = ace_bytes(0x00, 0x13, 0x001F_01FF, &sid);
    let ace = parse_ace(&bytes, 0, bytes.len() as u16).expect("the ACE header is in bounds");
    assert_eq!(ace.ace_type, 0x00);
    assert!(ace.is_allow() && !ace.is_deny());
    assert_eq!(ace.access_mask, Some(0x001F_01FF));
    assert_eq!(
        ace.sid.as_ref().map(|s| s.to_string()).as_deref(),
        Some("S-1-5-18")
    );
    assert_eq!(ace.body_error, None);
    assert_eq!(
        ace_flag_names(ace.flags),
        vec!["OBJECT_INHERIT", "CONTAINER_INHERIT", "INHERITED"]
    );
    assert_eq!(ace_effect(ace.ace_type), "allow");
}

#[test]
fn parse_ace_steps_over_the_guids_of_an_object_ace_to_reach_the_trustee() {
    // Object ACE with both ObjectType and InheritedObjectType present: the SID
    // sits 32 bytes further along than in a basic ACE. Reading it at the basic
    // offset would decode a GUID as a SID.
    let sid = sid_bytes(5, &[32, 544]);
    let mut tail: Vec<u8> = 0x3u32.to_le_bytes().to_vec();
    tail.extend_from_slice(&[0xAA; 16]);
    tail.extend_from_slice(&[0xBB; 16]);
    tail.extend_from_slice(&sid);
    let bytes = ace_bytes(0x05, 0x00, 0x0002_0000, &tail);

    let ace = parse_ace(&bytes, 0, bytes.len() as u16).expect("the ACE header is in bounds");
    assert_eq!(ace.object_flags, Some(0x3));
    assert_eq!(
        ace.sid.as_ref().map(|s| s.to_string()).as_deref(),
        Some("S-1-5-32-544")
    );
    assert_eq!(ace.body_error, None);
}

#[test]
fn parse_ace_reports_an_unmodelled_body_instead_of_guessing_a_trustee() {
    // A compound ACE (0x04) does not put its SID at the basic offset. Decoding
    // it there would name the wrong principal, so the trustee stays absent and
    // the reason is recorded.
    let sid = sid_bytes(5, &[18]);
    let bytes = ace_bytes(0x04, 0x00, 0x001F_01FF, &sid);
    let ace = parse_ace(&bytes, 0, bytes.len() as u16).expect("the ACE header is in bounds");
    assert_eq!(ace.sid, None);
    let reason = ace
        .body_error
        .clone()
        .expect("an unmodelled body must say so");
    assert!(reason.contains("0x04"), "got {reason}");
    assert!(ace.trustee_label().contains("not decoded"));
    assert_eq!(ace_effect(0x04), "unknown");
}

#[test]
fn parse_ace_returns_nothing_when_its_header_lies_outside_the_buffer() {
    assert!(parse_ace(&[0u8; 2], 0, 8).is_none());
    assert!(parse_ace(&[0u8; 32], 30, 8).is_none());
}

#[test]
fn an_ace_too_short_for_an_access_mask_reports_the_shortfall() {
    let bytes = vec![0x00, 0x00, 0x06, 0x00, 0xFF, 0xFF];
    let ace = parse_ace(&bytes, 0, 6).expect("the ACE header is in bounds");
    assert_eq!(ace.access_mask, None);
    assert!(ace
        .body_error
        .as_deref()
        .unwrap_or_default()
        .contains("access mask"));
}

// --- ACL decoding ------------------------------------------------------------

#[test]
fn parse_acl_walks_by_ace_size_so_an_unknown_ace_cannot_desync_the_list() {
    let known = sid_bytes(5, &[18]);
    // An unmodelled ACE type carrying extra trailing bytes sits between two
    // ordinary ACEs; advancing by anything but ace_size would misread the third.
    let odd = ace_bytes(0x7F, 0x00, 0x0000_0001, &[0xCC; 24]);
    let last_sid = sid_bytes(5, &[32, 545]);
    let acl = acl_bytes(
        2,
        &[
            ace_bytes(0x00, 0x00, 0x001F_01FF, &known),
            odd,
            ace_bytes(0x00, 0x00, 0x0012_0089, &last_sid),
        ],
    );

    let parsed = parse_acl(&acl, 0).expect("a well-formed ACL must decode");
    assert_eq!(parsed.aces.len(), 3);
    assert!(!parsed.truncated);
    assert_eq!(
        parsed.aces[2]
            .sid
            .as_ref()
            .map(|s| s.to_string())
            .as_deref(),
        Some("S-1-5-32-545"),
        "the ACE after the unknown one must still be located correctly"
    );
    assert!(parsed.aces[1].sid.is_none());
}

#[test]
fn parse_acl_flags_truncation_when_it_declares_more_aces_than_it_holds() {
    let sid = sid_bytes(5, &[18]);
    let mut acl = acl_bytes(2, &[ace_bytes(0x00, 0x00, 0x001F_01FF, &sid)]);
    // Claim four ACEs while carrying one.
    acl[4..6].copy_from_slice(&4u16.to_le_bytes());

    let parsed = parse_acl(&acl, 0).expect("the header still decodes");
    assert_eq!(parsed.declared_ace_count, 4);
    assert_eq!(parsed.aces.len(), 1);
    assert!(parsed.truncated, "a short ACL must never look complete");
    assert!(parsed
        .truncation_reason
        .as_deref()
        .unwrap_or_default()
        .contains("declares 4"));
}

#[test]
fn parse_acl_stops_when_an_ace_declares_an_unusable_size() {
    let sid = sid_bytes(5, &[18]);
    let mut acl = acl_bytes(
        2,
        &[
            ace_bytes(0x00, 0x00, 0x001F_01FF, &sid),
            ace_bytes(0x00, 0x00, 0x001F_01FF, &sid),
        ],
    );
    // Zero the second ACE's size: without the guard this loops forever.
    let second = ACL_HEADER_LEN + 8 + sid.len();
    acl[second + 2..second + 4].copy_from_slice(&0u16.to_le_bytes());

    let parsed = parse_acl(&acl, 0).expect("the header still decodes");
    assert_eq!(parsed.aces.len(), 1);
    assert!(parsed.truncated);
    assert!(parsed
        .truncation_reason
        .as_deref()
        .unwrap_or_default()
        .contains("unusable size"));
}

#[test]
fn parse_acl_rejects_a_header_that_does_not_fit_or_declares_an_impossible_size() {
    assert!(matches!(
        parse_acl(&[2u8, 0, 8, 0], 0),
        Err(SdsError::AclTruncated { .. })
    ));
    let mut acl = acl_bytes(2, &[]);
    acl[2..4].copy_from_slice(&4u16.to_le_bytes());
    assert!(matches!(
        parse_acl(&acl, 0),
        Err(SdsError::AclSizeInvalid { acl_size: 4, .. })
    ));
}

// --- descriptor decoding -----------------------------------------------------

#[test]
fn parse_security_descriptor_decodes_owner_group_dacl_and_sacl() {
    let descriptor =
        parse_security_descriptor(&canonical_descriptor()).expect("the fixture must decode");

    assert_eq!(
        descriptor.owner.as_ref().map(|s| s.to_string()).as_deref(),
        Some("S-1-5-32-544")
    );
    assert_eq!(
        descriptor.owner_label().as_deref(),
        Some("Administrators"),
        "a well-known owner must be named"
    );
    assert_eq!(
        descriptor.group.as_ref().map(|s| s.to_string()).as_deref(),
        Some("S-1-5-21-1-2-3-513")
    );

    let dacl = descriptor.dacl.acl().expect("the DACL must be present");
    assert_eq!(dacl.aces.len(), 4);
    assert_eq!(dacl.declared_ace_count, 4);
    assert!(!dacl.truncated);
    assert!(dacl.aces[0].is_allow());
    assert_eq!(dacl.aces[0].access_mask, Some(0x001F_01FF));
    assert!(dacl.aces[3].is_deny(), "the last ACE denies Guests");

    let sacl = descriptor.sacl.acl().expect("the SACL must be present");
    assert_eq!(sacl.aces.len(), 1);
    assert_eq!(descriptor.integrity_level(), Some("Medium"));
    assert!(!descriptor.partial);
    assert!(!descriptor.no_dacl_full_access());

    let summary = descriptor.permission_summary();
    assert!(summary.contains("Owner: Administrators"), "got {summary}");
    assert!(
        summary.contains("Local System = Full Control"),
        "got {summary}"
    );
    assert!(summary.contains("DENY Guests"), "got {summary}");
    assert!(summary.contains("Integrity: Medium"), "got {summary}");
}

#[test]
fn an_absent_dacl_grants_everyone_full_access_while_an_empty_dacl_grants_nobody() {
    let owner = sid_bytes(5, &[18]);

    // SE_DACL_PRESENT clear: there is no DACL, so every principal has full
    // access. Reporting this as "no permissions" inverts the finding.
    let absent = descriptor_bytes(SE_SELF_RELATIVE, Some(&owner), None, None, None);
    let d = parse_security_descriptor(&absent).expect("the descriptor must decode");
    assert_eq!(d.dacl, AclPresence::Absent);
    assert_eq!(d.dacl.state(), "absent");
    assert!(d.no_dacl_full_access());
    assert!(
        d.permission_summary().contains("everyone has full access"),
        "got {}",
        d.permission_summary()
    );

    // SE_DACL_PRESENT set with zero ACEs: an empty DACL denies everybody.
    let empty_acl = acl_bytes(2, &[]);
    let empty = descriptor_bytes(
        SE_SELF_RELATIVE | SE_DACL_PRESENT,
        Some(&owner),
        None,
        None,
        Some(&empty_acl),
    );
    let d = parse_security_descriptor(&empty).expect("the descriptor must decode");
    assert_eq!(d.dacl.state(), "present");
    assert_eq!(d.dacl.acl().map(|a| a.aces.len()), Some(0));
    assert!(!d.no_dacl_full_access());
    assert!(
        d.permission_summary()
            .contains("empty (no access granted to anyone)"),
        "got {}",
        d.permission_summary()
    );
}

#[test]
fn a_null_dacl_is_reported_as_unrestricted_and_not_as_absent() {
    let owner = sid_bytes(5, &[18]);
    let mut bytes = descriptor_bytes(
        SE_SELF_RELATIVE | SE_DACL_PRESENT,
        Some(&owner),
        None,
        None,
        None,
    );
    // The present bit with a zero offset is a NULL DACL.
    bytes[2..4].copy_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
    let d = parse_security_descriptor(&bytes).expect("the descriptor must decode");
    assert_eq!(d.dacl, AclPresence::Null);
    assert_eq!(d.dacl.state(), "null");
    assert!(d.no_dacl_full_access());
}

#[test]
fn parse_security_descriptor_refuses_a_descriptor_that_is_not_self_relative() {
    // Without SE_SELF_RELATIVE the owner/group/ACL fields are process memory
    // pointers; following them as offsets would invent an owner from unrelated
    // bytes.
    let owner = sid_bytes(5, &[18]);
    let bytes = descriptor_bytes(SE_DACL_PRESENT, Some(&owner), None, None, None);
    let err = parse_security_descriptor(&bytes).expect_err("this must be refused");
    assert!(matches!(err, SdsError::NotSelfRelative { .. }));
    assert!(err.to_string().contains("SE_SELF_RELATIVE"));
}

#[test]
fn parse_security_descriptor_refuses_a_short_buffer_or_an_unknown_revision() {
    assert!(matches!(
        parse_security_descriptor(&[0u8; 8]),
        Err(SdsError::DescriptorTruncated { len: 8 })
    ));
    let mut bytes = canonical_descriptor();
    bytes[0] = 3;
    assert!(matches!(
        parse_security_descriptor(&bytes),
        Err(SdsError::UnsupportedRevision { revision: 3 })
    ));
}

#[test]
fn a_bad_owner_offset_leaves_the_owner_undecoded_but_keeps_the_dacl() {
    let mut bytes = canonical_descriptor();
    // Point the owner past the end of the descriptor.
    bytes[4..8].copy_from_slice(&9_999u32.to_le_bytes());

    let d = parse_security_descriptor(&bytes).expect("the rest must still decode");
    assert!(d.owner.is_none(), "a bad offset must not yield an owner");
    let reason = d.owner_error.clone().expect("the failure must be named");
    assert!(reason.contains("owner SID"), "got {reason}");
    assert!(d.partial, "a partial descriptor must say so");
    assert_eq!(
        d.dacl.acl().map(|a| a.aces.len()),
        Some(4),
        "a bad owner must not discard a good DACL"
    );
    assert!(
        d.permission_summary().contains("Owner: not decoded"),
        "got {}",
        d.permission_summary()
    );
}

#[test]
fn an_unreadable_dacl_is_distinguishable_from_an_absent_one() {
    let mut bytes = canonical_descriptor();
    // Point the DACL past the end: access is now UNKNOWN, which must not read
    // as "no DACL, everyone has access".
    bytes[16..20].copy_from_slice(&9_999u32.to_le_bytes());

    let d = parse_security_descriptor(&bytes).expect("the rest must still decode");
    assert_eq!(d.dacl.state(), "unreadable");
    assert!(!d.no_dacl_full_access());
    assert!(d.partial);
    assert!(
        d.permission_summary().contains("access unknown"),
        "got {}",
        d.permission_summary()
    );
}

#[test]
fn a_protected_dacl_is_surfaced_as_broken_inheritance() {
    let owner = sid_bytes(5, &[18]);
    let dacl = acl_bytes(2, &[ace_bytes(0x00, 0x00, 0x001F_01FF, &owner)]);
    let bytes = descriptor_bytes(
        SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED,
        Some(&owner),
        None,
        None,
        Some(&dacl),
    );
    let d = parse_security_descriptor(&bytes).expect("the descriptor must decode");
    assert!(d.dacl_protected());
    assert!(control_flag_names(d.control).contains(&"SE_DACL_PROTECTED"));
}

#[test]
fn a_descriptor_without_a_mandatory_label_reports_no_integrity_level() {
    let owner = sid_bytes(5, &[18]);
    let dacl = acl_bytes(2, &[ace_bytes(0x00, 0x00, 0x001F_01FF, &owner)]);
    let bytes = descriptor_bytes(
        SE_SELF_RELATIVE | SE_DACL_PRESENT,
        Some(&owner),
        None,
        None,
        Some(&dacl),
    );
    let d = parse_security_descriptor(&bytes).expect("the descriptor must decode");
    assert_eq!(
        d.integrity_level(),
        None,
        "an absent label must stay absent, not default to Medium"
    );
}

// --- stream scanning ---------------------------------------------------------

#[test]
fn parse_sds_returns_one_entry_per_unique_security_id() {
    let first = canonical_descriptor();
    let owner = sid_bytes(5, &[19]);
    let second = descriptor_bytes(SE_SELF_RELATIVE, Some(&owner), None, None, None);

    let mut stream = sds_entry(0xAAAA_AAAA, 256, 0, &first);
    let second_offset = stream.len() as u64;
    stream.extend_from_slice(&sds_entry(0xBBBB_BBBB, 257, second_offset, &second));

    let scan = parse_sds(&stream);
    assert_eq!(scan.entries.len(), 2);
    assert_eq!(scan.duplicate_copies, 0);
    assert_eq!(scan.failed_entries, 0);
    assert_eq!(scan.mirror_recoveries, 0);
    assert!(!scan.entry_cap_reached);

    assert_eq!(scan.entries[0].security_id, 256);
    assert_eq!(scan.entries[0].hash, 0xAAAA_AAAA);
    assert_eq!(scan.entries[0].stream_offset, 0);
    assert!(!scan.entries[0].offset_mismatch);
    assert_eq!(scan.entries[1].security_id, 257);
    assert_eq!(scan.entries[1].stream_offset, second_offset);
    assert_eq!(
        scan.entries[1]
            .descriptor
            .as_ref()
            .expect("the second descriptor must decode")
            .owner_label()
            .as_deref(),
        Some("Local Service")
    );
}

#[test]
fn parse_sds_keeps_the_first_copy_of_a_mirrored_security_id() {
    let descriptor = canonical_descriptor();
    let mut stream = sds_entry(0xAAAA_AAAA, 256, 0, &descriptor);
    stream.resize(SDS_BLOCK_SIZE, 0);
    stream.extend_from_slice(&sds_entry(
        0xAAAA_AAAA,
        256,
        SDS_BLOCK_SIZE as u64,
        &descriptor,
    ));

    let scan = parse_sds(&stream);
    assert_eq!(scan.entries.len(), 1, "the mirror must not double-count");
    assert_eq!(scan.duplicate_copies, 1);
    assert_eq!(scan.entries[0].stream_offset, 0);
    assert!(matches!(scan.entries[0].origin, EntryOrigin::Primary));
}

#[test]
fn parse_sds_steps_over_block_padding_and_resumes_in_the_next_block() {
    // NTFS pads out to the 256 KiB boundary rather than letting an entry
    // straddle it. Treating that padding as end-of-stream would silently drop
    // every descriptor in later blocks.
    let first = canonical_descriptor();
    let owner = sid_bytes(5, &[18]);
    let second = descriptor_bytes(SE_SELF_RELATIVE, Some(&owner), None, None, None);

    let mut stream = sds_entry(1, 100, 0, &first);
    stream.resize(SDS_BLOCK_SIZE, 0);
    stream.extend_from_slice(&sds_entry(2, 101, SDS_BLOCK_SIZE as u64, &second));

    let scan = parse_sds(&stream);
    assert_eq!(scan.entries.len(), 2);
    assert_eq!(scan.entries[1].security_id, 101);
    assert_eq!(scan.entries[1].stream_offset, SDS_BLOCK_SIZE as u64);
}

#[test]
fn parse_sds_recovers_a_damaged_primary_entry_from_its_mirror_and_says_so() {
    let good = canonical_descriptor();
    let mut damaged = good.clone();
    damaged[0] = 0x5A; // corrupt the descriptor revision only

    let mut stream = sds_entry(0xC0FF_EE00, 512, 0, &damaged);
    stream.resize(SDS_BLOCK_SIZE, 0);
    stream.extend_from_slice(&sds_entry(0xC0FF_EE00, 512, 0, &good));

    let scan = parse_sds(&stream);
    assert_eq!(scan.entries.len(), 1);
    assert_eq!(scan.mirror_recoveries, 1);
    assert_eq!(scan.failed_entries, 0);

    let entry = &scan.entries[0];
    let descriptor = entry
        .descriptor
        .as_ref()
        .expect("the mirror copy must supply the descriptor");
    assert_eq!(descriptor.owner_label().as_deref(), Some("Administrators"));
    match &entry.origin {
        EntryOrigin::MirrorRecovered {
            primary_offset,
            mirror_offset,
            primary_error,
        } => {
            assert_eq!(*primary_offset, 0);
            assert_eq!(*mirror_offset, SDS_BLOCK_SIZE as u64);
            assert!(
                primary_error.contains("revision"),
                "the primary failure must be named, got {primary_error}"
            );
        }
        EntryOrigin::Primary => panic!("a recovered descriptor must not be reported as primary"),
    }
}

#[test]
fn parse_sds_heals_a_damaged_entry_from_a_later_copy_of_the_same_security_id() {
    // Here the primary's own header hash is damaged too, so the direct mirror
    // probe rejects the candidate; the later copy still heals the entry when
    // the scan reaches it.
    let good = canonical_descriptor();
    let mut damaged = good.clone();
    damaged[0] = 0x5A;

    let mut stream = sds_entry(0xDEAD_0000, 700, 0, &damaged);
    stream.resize(SDS_BLOCK_SIZE, 0);
    stream.extend_from_slice(&sds_entry(0xBEEF_0000, 700, 0, &good));

    let scan = parse_sds(&stream);
    assert_eq!(scan.entries.len(), 1);
    assert_eq!(scan.duplicate_copies, 1);
    assert_eq!(scan.mirror_recoveries, 1);
    assert_eq!(scan.failed_entries, 0);
    assert!(matches!(
        scan.entries[0].origin,
        EntryOrigin::MirrorRecovered { .. }
    ));
}

#[test]
fn parse_sds_reports_an_entry_whose_descriptor_cannot_be_decoded_anywhere() {
    let mut damaged = canonical_descriptor();
    damaged[0] = 0x5A;
    let stream = sds_entry(7, 900, 0, &damaged);

    let scan = parse_sds(&stream);
    assert_eq!(scan.entries.len(), 1, "the id must still be reported");
    assert_eq!(scan.failed_entries, 1);
    assert_eq!(scan.entries[0].security_id, 900);
    let err = scan.entries[0]
        .descriptor
        .as_ref()
        .expect_err("the descriptor must not decode");
    assert!(matches!(
        err,
        SdsError::UnsupportedRevision { revision: 0x5A }
    ));
}

#[test]
fn parse_sds_reports_an_entry_that_runs_past_the_end_of_the_stream() {
    let mut stream = sds_entry(3, 300, 0, &canonical_descriptor());
    // Claim far more bytes than the stream holds, as a truncated capture would.
    stream[16..20].copy_from_slice(&4096u32.to_le_bytes());
    stream.truncate(64);

    let scan = parse_sds(&stream);
    assert_eq!(scan.entries_past_end, 1);
    assert_eq!(scan.entries.len(), 1);
    assert!(matches!(
        scan.entries[0]
            .descriptor
            .as_ref()
            .expect_err("nothing can be decoded from bytes that are not there"),
        SdsError::EntryPastEndOfStream { .. }
    ));
}

#[test]
fn parse_sds_flags_an_entry_whose_declared_offset_disagrees_with_where_it_sits() {
    let stream = sds_entry(4, 400, 0x1234, &canonical_descriptor());
    let scan = parse_sds(&stream);
    assert_eq!(scan.entries.len(), 1);
    assert!(
        scan.entries[0].offset_mismatch,
        "an inconsistent store must not look intact"
    );
}

#[test]
fn parse_sds_stops_at_the_entry_cap_and_reports_that_it_did() {
    let descriptor = canonical_descriptor();
    let mut stream = sds_entry(1, 10, 0, &descriptor);
    let offset = stream.len() as u64;
    stream.extend_from_slice(&sds_entry(2, 11, offset, &descriptor));

    let scan = parse_sds_with_limits(&stream, 1);
    assert_eq!(scan.entries.len(), 1);
    assert!(
        scan.entry_cap_reached,
        "a capped scan must never be reported as the whole store"
    );
}

#[test]
fn an_entry_header_that_declares_more_than_the_size_ceiling_is_counted_not_silently_dropped() {
    // A corrupt or hostile entry_size must not be used to size a read, but the
    // security id it names must not vanish either: "this volume has no
    // descriptor 500" and "we refused to read descriptor 500" are different
    // findings.
    // A bare header followed by padding, so nothing else in the stream can be
    // mistaken for an entry and the assertion below is about this header alone.
    let mut stream = vec![0u8; 4096];
    stream[0..4].copy_from_slice(&5u32.to_le_bytes()); // hash
    stream[4..8].copy_from_slice(&500u32.to_le_bytes()); // security_id
    stream[8..16].copy_from_slice(&0u64.to_le_bytes()); // declared offset
    stream[16..20].copy_from_slice(&(MAX_SDS_ENTRY_SIZE + 1).to_le_bytes());

    let scan = parse_sds(&stream);
    assert_eq!(
        scan.oversize_entries, 1,
        "the refusal has to be visible on the store record"
    );
    assert!(
        scan.incomplete(),
        "a listing missing a refused id is not the whole store"
    );
    assert!(
        scan.entries.is_empty(),
        "an oversize length must never size a read"
    );
}

#[test]
fn an_entry_at_exactly_the_size_ceiling_is_still_read() {
    // The boundary matters: an off-by-one here would refuse legitimate large
    // descriptors and report the volume as having fewer than it does.
    let descriptor = canonical_descriptor();
    let mut stream = sds_entry(6, 600, 0, &descriptor);
    stream[16..20].copy_from_slice(&MAX_SDS_ENTRY_SIZE.to_le_bytes());
    stream.resize(MAX_SDS_ENTRY_SIZE as usize, 0);

    let scan = parse_sds(&stream);
    assert_eq!(scan.oversize_entries, 0);
    assert_eq!(scan.entries.len(), 1);
    assert_eq!(scan.entries[0].security_id, 600);
    assert!(scan.entries[0].descriptor.is_ok());
}

#[test]
fn a_scan_that_refused_nothing_and_hit_no_cap_reports_itself_complete() {
    let scan = parse_sds(&sds_entry(7, 700, 0, &canonical_descriptor()));
    assert_eq!(scan.oversize_entries, 0);
    assert!(!scan.entry_cap_reached);
    assert!(
        !scan.incomplete(),
        "flagging a complete store would make the flag worthless"
    );
}

#[test]
fn parse_sds_returns_an_empty_scan_for_an_empty_or_all_padding_stream() {
    let scan = parse_sds(&[]);
    assert!(scan.entries.is_empty());
    assert_eq!(scan.bytes_scanned, 0);

    let scan = parse_sds(&vec![0u8; 4096]);
    assert!(scan.entries.is_empty());
    assert!(!scan.entry_cap_reached);
    assert_eq!(scan.failed_entries, 0);
}

// --- hostile input -----------------------------------------------------------

/// Deterministic pseudo-random bytes; a seeded LCG keeps the test reproducible
/// so a failure can be replayed exactly.
fn pseudo_random(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

#[test]
fn hostile_and_random_input_returns_without_panicking_or_looping() {
    // The assertion is that each call RETURNS: this parser runs against
    // attacker-supplied disk images.
    for seed in 0..16u64 {
        let bytes = pseudo_random(seed, 8_192);
        let scan = parse_sds(&bytes);
        assert!(scan.entries.len() <= MAX_SDS_ENTRIES);
        let _ = parse_security_descriptor(&bytes);
        let _ = parse_acl(&bytes, 0);
        let _ = parse_sid(&bytes, 0);
        let _ = parse_ace(&bytes, 0, u16::MAX);
    }

    // All-ones: every length field claims the maximum.
    let ones = vec![0xFFu8; 4_096];
    let _ = parse_sds(&ones);
    let _ = parse_security_descriptor(&ones);
    let _ = parse_acl(&ones, 0);
    let _ = parse_sid(&ones, 0);

    // A descriptor whose every offset points at itself.
    let mut looping = vec![1u8, 0];
    looping.extend_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    for _ in 0..4 {
        looping.extend_from_slice(&4u32.to_le_bytes());
    }
    let _ = parse_security_descriptor(&looping);

    // An ACL whose size and ACE count are both maximal.
    let mut acl = vec![2u8, 0];
    acl.extend_from_slice(&u16::MAX.to_le_bytes());
    acl.extend_from_slice(&u16::MAX.to_le_bytes());
    acl.extend_from_slice(&[0, 0]);
    acl.resize(256, 0);
    let parsed = parse_acl(&acl, 0).expect("the header decodes");
    assert!(parsed.truncated, "a fabricated ACE count must be flagged");
}

// --- A mandatory label is not an access right (HUNT-126) ---------------------

/// A `SYSTEM_MANDATORY_LABEL` ACE's mask is a **policy**, not a set of access
/// rights, and rendering it through the access-right table fabricates a
/// permission that was never granted.
///
/// The bits collide exactly: `SYSTEM_MANDATORY_POLICY_NO_WRITE_UP` is `0x1`,
/// and `0x1` in a file access mask is `FILE_READ_DATA`. So a Medium-integrity
/// label — on essentially every user file on a modern Windows system — rendered
/// as "Read Data / List Directory", which is a statement about who may read the
/// file, from a structure that says nothing of the kind.
///
/// This shape is not hypothetical: `SYSTEM_MANDATORY_LABEL` ACEs (type 0x11)
/// with masks `0x1` and `0x3` were found in 14 descriptors of the real `SYSTEM`
/// hive and 9 of `NTUSER-WIN7` while planning §2.5.
#[test]
fn a_mandatory_label_ace_is_not_rendered_as_an_access_right() {
    let medium = sid_bytes(16, &[0x2000]);
    let sacl = acl_bytes(2, &[ace_bytes(0x11, 0x00, 0x0000_0001, &medium)]);
    let sd = descriptor_bytes(
        SE_SELF_RELATIVE | SE_SACL_PRESENT,
        Some(&sid_bytes(5, &[32, 544])),
        None,
        Some(&sacl),
        None,
    );
    let d = parse_security_descriptor(&sd).expect("the descriptor decodes");
    let summary = d.permission_summary();

    assert!(
        !summary.contains("Read Data"),
        "a mandatory-label mask must never be rendered as a file access right; got {summary:?}"
    );
    assert!(
        summary.contains("NO_WRITE_UP"),
        "the label's policy must be named for what it is; got {summary:?}"
    );
    // The hexadecimal is always kept, so the rendering is never the only record.
    assert!(summary.contains("0x00000001"), "got {summary:?}");
}

/// The two mandatory policy bits Windows defines, and a combination of them.
#[test]
fn the_mandatory_policy_bits_are_named_individually() {
    assert!(describe_mandatory_policy(0x1).contains("NO_WRITE_UP"));
    assert!(describe_mandatory_policy(0x2).contains("NO_READ_UP"));
    assert!(describe_mandatory_policy(0x4).contains("NO_EXECUTE_UP"));
    let both = describe_mandatory_policy(0x3);
    assert!(
        both.contains("NO_WRITE_UP") && both.contains("NO_READ_UP"),
        "got {both:?}"
    );
    // An unnamed bit is reported, never dropped.
    let odd = describe_mandatory_policy(0x9);
    assert!(
        odd.contains("NO_WRITE_UP") && odd.contains("0x00000008"),
        "got {odd:?}"
    );
}

// --- An inherit-only ACE grants nothing here (HUNT-126) ----------------------

/// An ACE carrying `INHERIT_ONLY_ACE` does **not** apply to the object holding
/// it: it exists to be inherited by children. Listing it in a summary of what
/// is granted on *this* object states a permission that is not in force.
///
/// Four of the eight ACEs in the real `SAM` root descriptor carry exactly
/// `0x0A` — `CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE` — so on real evidence
/// this is a majority of the list, not an edge case, and the un-marked summary
/// was overstating the ACL of the single most security-relevant key in Windows.
#[test]
fn an_inherit_only_ace_is_marked_as_not_applying_to_this_object() {
    let users = sid_bytes(5, &[32, 545]);
    let admins = sid_bytes(5, &[32, 544]);
    let dacl = acl_bytes(
        2,
        &[
            ace_bytes(0x00, 0x00, 0x0002_0019, &users),
            // CONTAINER_INHERIT | INHERIT_ONLY, the real SAM shape.
            ace_bytes(0x00, 0x0A, 0x1000_0000, &admins),
        ],
    );
    let sd = descriptor_bytes(
        SE_SELF_RELATIVE | SE_DACL_PRESENT,
        Some(&admins),
        None,
        None,
        Some(&dacl),
    );
    let d = parse_security_descriptor(&sd).expect("decodes");
    let summary = d.permission_summary();

    assert!(
        summary.contains("inherit-only"),
        "an ACE that grants nothing on this object must say so; got {summary:?}"
    );
    // And the ACE that DOES apply must not be marked.
    let applies = summary
        .split(", ")
        .find(|part| part.contains("0x00020019"))
        .unwrap_or_default();
    assert!(
        !applies.contains("inherit-only"),
        "an ACE in force must not be marked inherit-only; got {applies:?}"
    );
}

/// `Ace::applies_to_this_object` is the predicate the summary rests on, and it
/// is worth pinning on its own: `INHERIT_ONLY_ACE` is `0x08`, and it is only
/// meaningful alongside an inherit flag.
#[test]
fn inherit_only_is_the_only_flag_that_withholds_an_ace_from_its_own_object() {
    let sid = sid_bytes(5, &[18]);
    for (flags, applies) in [
        (0x00u8, true), // no inheritance at all
        (0x02, true),   // CONTAINER_INHERIT: applies here AND is inherited
        (0x01, true),   // OBJECT_INHERIT: same
        (0x10, true),   // INHERITED_ACE: it came from the parent, but it applies
        (0x08, false),  // INHERIT_ONLY
        (0x0A, false),  // CONTAINER_INHERIT | INHERIT_ONLY -- the real SAM shape
        (0x09, false),  // OBJECT_INHERIT | INHERIT_ONLY
    ] {
        let acl = acl_bytes(2, &[ace_bytes(0x00, flags, 0x000F_003F, &sid)]);
        let parsed = parse_acl(&acl, 0).expect("decodes");
        assert_eq!(
            parsed.aces[0].applies_to_this_object(),
            applies,
            "ACE flags 0x{flags:02X}"
        );
    }
}

// --- Registry rights are not file rights (§2.5) ------------------------------

/// The sixteen masks that actually occur across the twelve real hives under
/// `reference/plaso/test_data/`, in frequency order.
///
/// This list is the fixture vocabulary for registry ACLs, and it is here
/// because **not one of these is a file composite**: rendered through the file
/// table, every one of them gets a wrong name or bare hexadecimal. `HUNT-122`
/// is what a fixture vocabulary the evidence does not produce costs.
const REAL_REGISTRY_MASKS: &[u32] = &[
    0x000F_003F, // KEY_ALL_ACCESS
    0x0002_0019, // KEY_READ (and KEY_EXECUTE, which is the same value)
    0x1000_0000, // GENERIC_ALL -- 507 times in SOFTWARE alone
    0x8000_0000, // GENERIC_READ
    0x0002_001F,
    0x0003_001F,
    0x0003_003F,
    0x0002_0000, // READ_CONTROL alone
    0x0002_001D,
    0x0002_0039,
    0xA000_0000,
    0xE000_0000,
    0xC001_0000,
    0x101F_FFFF,
    0x0006_0000, // READ_CONTROL | WRITE_DAC -- what Administrators get on SAM's children
    0x0000_0002, // KEY_SET_VALUE alone
];

/// A registry key's rights must be named with registry names.
///
/// `0x000F003F` is `KEY_ALL_ACCESS`. Through the file table it is not a
/// composite at all, and its low bits would read as "Read Data / Write Data /
/// Append Data / …" — file operations that have no meaning on a key.
#[test]
fn a_registry_mask_is_named_with_registry_rights() {
    assert_eq!(
        describe_access_mask(ObjectKind::RegistryKey, 0x000F_003F),
        "KEY_ALL_ACCESS (0x000F003F)"
    );
    assert_eq!(
        describe_access_mask(ObjectKind::RegistryKey, 0x0002_0019),
        "KEY_READ (0x00020019)"
    );
    assert_eq!(
        describe_access_mask(ObjectKind::RegistryKey, 0x0002_0006),
        "KEY_WRITE (0x00020006)"
    );

    // A mask that is not a composite is spelled out in registry terms.
    let set_value = describe_access_mask(ObjectKind::RegistryKey, 0x0000_0002);
    assert!(set_value.contains("KEY_SET_VALUE"), "got {set_value:?}");
    assert!(
        !set_value.contains("Write Data"),
        "a key has no data to write; got {set_value:?}"
    );
}

/// The same bits mean different things on the two object kinds, and the
/// renderer must not be able to answer without being told which it has.
#[test]
fn the_same_bits_read_differently_on_a_file_and_on_a_key() {
    let file = describe_access_mask(ObjectKind::File, 0x0000_0001);
    let key = describe_access_mask(ObjectKind::RegistryKey, 0x0000_0001);
    assert!(file.contains("Read Data"), "got {file:?}");
    assert!(key.contains("KEY_QUERY_VALUE"), "got {key:?}");
    assert_ne!(file, key);
}

/// `KEY_READ` and `KEY_EXECUTE` are the **same value**, `0x20019`.
///
/// An exact-match table must therefore name it once and say so, rather than
/// picking one of the two names and leaving a reader to think the other was
/// ruled out.
#[test]
fn key_read_and_key_execute_are_one_value_and_are_named_as_such() {
    let named = describe_access_mask(ObjectKind::RegistryKey, 0x0002_0019);
    assert!(named.starts_with("KEY_READ"), "got {named:?}");
    assert_eq!(
        registry_composite_name(0x0002_0019),
        Some("KEY_READ"),
        "the composite table must hold one entry for the value, not two"
    );
}

/// Generic rights are named generically and **never** translated into specific
/// ones.
///
/// `GENERIC_ALL` on a key maps to `KEY_ALL_ACCESS` only through the kernel's
/// generic mapping for the key object type, which is not in the hive. Naming it
/// as the specific rights would assert a mapping this tool did not read.
/// `GENERIC_ALL` is the third most common mask in the corpus — 507 occurrences
/// in `SOFTWARE` alone — so this is the common path, not a nicety.
#[test]
fn generic_rights_are_not_translated_into_specific_ones() {
    for (mask, name) in [
        (0x1000_0000u32, "GENERIC_ALL"),
        (0x8000_0000, "GENERIC_READ"),
        (0x4000_0000, "GENERIC_WRITE"),
        (0x2000_0000, "GENERIC_EXECUTE"),
    ] {
        let named = describe_access_mask(ObjectKind::RegistryKey, mask);
        assert!(named.contains(name), "got {named:?}");
        assert!(
            !named.contains("KEY_ALL_ACCESS") && !named.contains("KEY_QUERY_VALUE"),
            "a generic right must not be translated into specific ones; got {named:?}"
        );
    }
}

/// Every mask the real hives hold keeps its hexadecimal, and every bit the
/// table cannot name is disclosed rather than dropped.
///
/// This assertion was written the other way round first — "no real mask has an
/// unnamed bit" — and the evidence refuted it. `0x101FFFFF` occurs in the corpus
/// and sets `0x0000FCC0`, bits the registry does **not** define as key rights
/// (`0x40`, `0x80`, and `0x400` through `0x8000` are not `KEY_*` values). So
/// the renderer is right and the assumption was wrong: those bits are reported
/// as unnamed, because naming them would invent rights Windows does not define
/// for a key.
///
/// Fifteen of the sixteen real masks name every bit. The point of the test is
/// that the sixteenth is *disclosed*.
#[test]
fn every_real_registry_mask_keeps_its_hex_and_discloses_what_it_cannot_name() {
    for mask in REAL_REGISTRY_MASKS {
        let named = describe_access_mask(ObjectKind::RegistryKey, *mask);
        assert!(
            named.contains(&format!("0x{mask:08X}")),
            "mask 0x{mask:08X} lost its hexadecimal: {named:?}"
        );
        let covered = REGISTRY_RIGHT_BITS_FOR_TEST | STANDARD_RIGHT_BITS_FOR_TEST;
        if mask & !covered != 0 {
            assert!(
                named.contains("unnamed bits"),
                "mask 0x{mask:08X} sets bits the table cannot name and must say so: {named:?}"
            );
        } else {
            assert!(
                !named.contains("unnamed bits"),
                "mask 0x{mask:08X} is fully nameable and must not claim otherwise: {named:?}"
            );
        }
    }
}

/// Every bit the two registry tables name, so the test above can tell a
/// genuinely unnameable bit from a gap in the table.
const REGISTRY_RIGHT_BITS_FOR_TEST: u32 = 0x0000_033F;
const STANDARD_RIGHT_BITS_FOR_TEST: u32 = 0xF31F_0000;

/// The one real mask that is not fully nameable, called out by name.
///
/// `0x101FFFFF` is `GENERIC_ALL` over every low bit set, and a registry key
/// has no rights at `0x40`, `0x80`, or `0x400`-`0x8000`. An examiner reading
/// this needs to see that those bits were set in the evidence and that this
/// tool would not name them.
#[test]
fn the_all_bits_mask_from_the_corpus_discloses_its_undefined_bits() {
    let named = describe_access_mask(ObjectKind::RegistryKey, 0x101F_FFFF);
    assert!(named.contains("GENERIC_ALL"), "got {named:?}");
    assert!(named.contains("unnamed bits 0x0000FCC0"), "got {named:?}");
    assert!(named.contains("0x101FFFFF"), "got {named:?}");
}

/// A bit no table names is reported as unnamed rather than dropped.
///
/// The bits `0x0000_8000`-ish range is reserved on a key; if one turns up, the
/// examiner must see that it was there and unrecognised.
#[test]
fn a_bit_the_registry_table_cannot_name_is_reported_not_dropped() {
    let named = describe_access_mask(ObjectKind::RegistryKey, 0x0000_0800);
    assert!(named.contains("0x00000800"), "got {named:?}");
}
