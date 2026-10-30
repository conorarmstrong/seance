//! Local accounts from `SAM` — stated before they were decoded.
//!
//! # Ground truth
//!
//! `reference/plaso/test_data/SAM`, a real Windows 7-era hive, read cell by
//! cell. Three accounts, and the `F` value is exactly 80 bytes on all three:
//!
//! ```text
//! RID 500 (000001F4) Administrator  F 80 B  V 592 B
//! RID 501 (000001F5) Guest          F 80 B  V 528 B
//! RID 1000 (000003E8) Preston       F 80 B  V 472 B
//! ```
//!
//! The `F` bytes, verbatim:
//!
//! ```text
//! 500  02 00 01 00 00 00 00 00  18 d2 12 a1 fc 88 cb 01
//!      00 00 00 00 00 00 00 00  46 8f 64 cc fd 88 cb 01
//!      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
//!      f4 01 00 00 01 02 00 00  11 02 00 00 00 00 00 00
//!      00 00 06 00 01 00 00 00  00 00 00 00 88 52 35 00
//! 501  02 00 01 00 00 00 00 00  00 00 00 00 00 00 00 00
//!      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
//!      ff ff ff ff ff ff ff 7f  00 00 00 00 00 00 00 00
//!      f5 01 00 00 01 02 00 00  15 02 00 00 00 00 00 00
//!      00 00 00 00 00 00 00 00  00 00 00 00 88 52 35 00
//! 1000 02 00 01 00 00 00 00 00  d0 01 4d 90 5a dc cf 01
//!      00 00 00 00 00 00 00 00  8e 66 27 a0 a8 d7 cf 01
//!      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
//!      e8 03 00 00 01 02 00 00  10 00 00 00 01 00 e4 04
//!      00 00 04 00 01 00 00 00  00 00 71 00 bc ee 71 00
//! ```
//!
//! # How each field was established, and why the others are not read
//!
//! Only offsets the evidence **proves** are decoded. The proofs are in-file,
//! not recollections of a layout:
//!
//! * `+0x30` is the RID: it equals the hex key name on all three accounts.
//! * `+0x08` is the last logon: RID 1000's value is byte-identical to its own
//!   key's `nk` last-written time and is 6.0 ms before the hive header's own
//!   last-written time — it is the last write this hive ever took.
//! * `+0x18` is the last password set: RID 1000's value is 0.72 s after the
//!   instant at which three sibling keys (`Users`, `Users\Names\Preston`,
//!   `Groups\00000201`) were written together, which is account creation, and
//!   it is six days *before* `+0x08`, so the two are not interchangeable.
//! * `+0x38` is the account-control word: Guest's differs from
//!   Administrator's by exactly one bit, `0x0004`, and Guest is precisely the
//!   account whose password is not required — and the bit is set on exactly
//!   the one account with no hash material.
//! * `+0x42` is a `u16` logon count (6 / 0 / 4). It varies per account, and
//!   its only zero falls on the one account that never logged on. Read as a
//!   `u32` at `+0x40` it would be 393,216.
//!
//! Each of the five is independently corroborated by plaso's own checked-in
//! test for this same file, which asserts `last_login_time`
//! `2010-11-20T21:48:12.5692440+00:00`, `last_password_set_time`
//! `2010-11-20T21:56:34.7436870+00:00` and `login_count` 6 for RID 500.
//!
//! **What is deliberately not decoded**, because this hive cannot establish it:
//! the account-expiry slot (`+0x20`: zero on two accounts and the `0x7FFF…`
//! never-sentinel on the third — a sentinel proves the slot is optional, not
//! what it means), the bad-password time (`+0x28`: zero on all three), the
//! failed-count `u16` (`+0x40`: zero on all three, so its offset cannot be
//! told apart from any other always-zero field), `+0x10` (zero on all three),
//! and the country/codepage pair (`+0x3c`/`+0x3e`: non-zero on one account
//! only). Each is named on the record as not read, rather than omitted.

use super::sam::*;

/// The real `F` bytes, so every test below is driven by the evidence.
const F_500: [u8; 80] = [
    0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0xd2, 0x12, 0xa1, 0xfc, 0x88, 0xcb, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x8f, 0x64, 0xcc, 0xfd, 0x88, 0xcb, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf4, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x52, 0x35, 0x00,
];
const F_501: [u8; 80] = [
    0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf5, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x15, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x52, 0x35, 0x00,
];
const F_1000: [u8; 80] = [
    0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x01, 0x4d, 0x90, 0x5a, 0xdc, 0xcf, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8e, 0x66, 0x27, 0xa0, 0xa8, 0xd7, 0xcf, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe8, 0x03, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0xe4, 0x04,
    0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71, 0x00, 0xbc, 0xee, 0x71, 0x00,
];

// --- Recognising the keys --------------------------------------------------

/// The account key, the name-index key, and the containers that are neither.
#[test]
fn a_sam_account_key_is_recognised_and_its_neighbours_are_not() {
    const ROOT: &str = r"CMI-CreateHive{899121E8}\SAM\Domains\Account";
    assert_eq!(
        sam_account_key(&format!(r"{ROOT}\Users\000001F4")),
        Some("000001F4".to_string())
    );
    assert_eq!(
        sam_account_key(&format!(r"{ROOT}\Users\000003E8")),
        Some("000003E8".to_string())
    );
    assert_eq!(
        sam_name_key(&format!(r"{ROOT}\Users\Names\Administrator")),
        Some("Administrator".to_string())
    );
    // A space in a name is real: the CFReDS Hacking Case has `Mr. Evil`.
    assert_eq!(
        sam_name_key(&format!(r"{ROOT}\Users\Names\Mr. Evil")),
        Some("Mr. Evil".to_string())
    );
    // Containers and neighbours.
    for not_an_account in [
        format!(r"{ROOT}\Users"),
        format!(r"{ROOT}\Users\Names"),
        // `Names` is not an eight-hex-digit RID, and must not be read as one.
        format!(r"{ROOT}\Users\Names\Guest\Deeper"),
        format!(r"{ROOT}\Groups\00000201"),
        format!(r"{ROOT}\Aliases\00000220"),
        r"CMI-CreateHive{899121E8}\SAM\Domains\Builtin\Users\000001F4".to_string(),
    ] {
        assert_eq!(
            sam_account_key(&not_an_account),
            None,
            "must not be an account: {not_an_account}"
        );
    }
    for not_a_name in [
        format!(r"{ROOT}\Users\Names"),
        format!(r"{ROOT}\Users\000001F4"),
        format!(r"{ROOT}\Users\Names\Guest\Deeper"),
    ] {
        assert_eq!(
            sam_name_key(&not_a_name),
            None,
            "must not be a name: {not_a_name}"
        );
    }
}

// --- The F value -----------------------------------------------------------

/// The RID from `F` agrees with the key name, on all three real accounts.
#[test]
fn the_rid_in_the_f_value_agrees_with_the_key_name() {
    for (key_name, bytes, rid) in [
        ("000001F4", &F_500, 500u32),
        ("000001F5", &F_501, 501),
        ("000003E8", &F_1000, 1000),
    ] {
        let f = FValue::parse(bytes).expect("80 bytes parse");
        assert_eq!(f.rid, rid, "{key_name}");
        assert_eq!(
            rid_from_key_name(key_name),
            Some(rid),
            "the key name is the second, independent route"
        );
    }
}

/// A `F` whose RID disagrees with its key name is reported as a disagreement,
/// and neither number is dropped.
#[test]
fn a_rid_that_disagrees_with_the_key_name_is_stated() {
    let mut bytes = F_500;
    bytes[0x30] = 0xE8;
    bytes[0x31] = 0x03;
    let f = FValue::parse(&bytes).expect("still 80 bytes");
    let account = LocalAccount::new("000001F4", Some(f), None, 0);
    let j = account.to_json();
    assert_eq!(
        j["rid"],
        serde_json::json!(500),
        "the key name is the anchor"
    );
    assert_eq!(j["rid_in_f_value"], serde_json::json!(1000));
    let note = j["rid_conflict"].as_str().unwrap_or("");
    assert!(
        note.contains("500") && note.contains("1000"),
        "both numbers, so a reader can check it: {note}"
    );
}

/// The two times this evidence proves, and the account that has neither.
#[test]
fn the_logon_and_password_times_decode_to_their_known_answers() {
    let admin = FValue::parse(&F_500).expect("parse");
    assert_eq!(
        admin.last_logon_filetime,
        Some(0x01cb_88fc_a112_d218),
        "the raw value, so the offset is pinned and not just its rendering"
    );
    let j = LocalAccount::new("000001F4", Some(admin), Some("Administrator"), 0).to_json();
    assert!(
        j["last_logon"]
            .as_str()
            .unwrap_or("")
            .starts_with("2010-11-20T21:48:12.569244"),
        "got {:?} -- plaso's own test for this file asserts 21:48:12.5692440",
        j["last_logon"]
    );
    assert!(
        j["last_password_set"]
            .as_str()
            .unwrap_or("")
            .starts_with("2010-11-20T21:56:34.743687"),
        "got {:?}",
        j["last_password_set"]
    );
    assert_eq!(j["login_count"], serde_json::json!(6));

    let preston = FValue::parse(&F_1000).expect("parse");
    let j = LocalAccount::new("000003E8", Some(preston), Some("Preston"), 0).to_json();
    assert!(
        j["last_logon"]
            .as_str()
            .unwrap_or("")
            .starts_with("2014-09-30T02:59:34.316692"),
        "got {:?}",
        j["last_logon"]
    );
    assert_eq!(j["login_count"], serde_json::json!(4));
}

/// **The failure this decoder exists against.** Guest never logged on and
/// never had a password set, and both fields are zero.
///
/// A converter that runs unconditionally prints "Guest, last logon
/// 1601-01-01" — a fabricated logon event on an account that has never been
/// used. On this one hive it would do so at least eleven times across three
/// accounts.
#[test]
fn an_account_that_never_logged_on_gets_no_date_and_says_why() {
    let guest = FValue::parse(&F_501).expect("parse");
    assert_eq!(guest.last_logon_filetime, Some(0));
    let j = LocalAccount::new("000001F5", Some(guest), Some("Guest"), 0).to_json();
    assert!(
        j["last_logon"].is_null(),
        "got {:?} -- zero means not recorded",
        j["last_logon"]
    );
    assert!(j["last_password_set"].is_null());
    assert_eq!(j["login_count"], serde_json::json!(0));
    let why = j["last_logon_absent_reason"].as_str().unwrap_or("");
    assert!(
        why.to_lowercase().contains("not recorded") && why.contains("never"),
        "the absence is stated, not left as an empty cell: {why}"
    );
}

/// Every real account in this hive, and not one 1601 or far-future date among
/// the fields that carry dates.
///
/// The record's own PROSE says the words "1601-01-01" — that is the sentence
/// explaining why no such date is published — so this asserts on the date
/// fields rather than on the serialised record, which would pass only by
/// removing the explanation.
#[test]
fn no_account_in_the_real_hive_renders_a_sentinel_as_a_date() {
    for (key, bytes) in [
        ("000001F4", &F_500),
        ("000001F5", &F_501),
        ("000003E8", &F_1000),
    ] {
        let f = FValue::parse(bytes).expect("parse");
        let j = LocalAccount::new(key, Some(f), None, 0).to_json();
        for field in ["last_logon", "last_password_set"] {
            let Some(t) = j[field].as_str() else { continue };
            assert!(
                t.starts_with("20"),
                "{key}.{field} is {t:?}, which is not a date in this machine's lifetime"
            );
        }
        // And no field this build does not read has become one.
        for never in [
            "account_expires",
            "last_incorrect_password",
            "failed_login_count",
        ] {
            assert!(j.get(never).is_none(), "{key} published {never}");
        }
    }
}

/// The account-control bits this evidence exercised are named; the others are
/// reported as the bits they are and not named.
#[test]
fn the_account_control_bits_this_evidence_exercised_are_named_and_no_others() {
    let admin = FValue::parse(&F_500).expect("parse");
    assert_eq!(admin.account_control, 0x0211);
    let j = LocalAccount::new("000001F4", Some(admin), None, 0).to_json();
    assert_eq!(j["account_enabled"], serde_json::json!(false));
    assert_eq!(j["password_not_required"], serde_json::json!(false));
    let flags: Vec<&str> = j["account_control_flags"]
        .as_array()
        .expect("named flags")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        flags,
        vec!["disabled", "normal_account", "password_never_expires"]
    );

    let guest = FValue::parse(&F_501).expect("parse");
    let j = LocalAccount::new("000001F5", Some(guest), None, 0).to_json();
    assert_eq!(j["account_enabled"], serde_json::json!(false));
    assert_eq!(
        j["password_not_required"],
        serde_json::json!(true),
        "the one bit that differs from Administrator's word"
    );

    let preston = FValue::parse(&F_1000).expect("parse");
    let j = LocalAccount::new("000003E8", Some(preston), None, 0).to_json();
    assert_eq!(j["account_enabled"], serde_json::json!(true));
    assert_eq!(j["account_locked_out"], serde_json::Value::Null);
    let why = j["account_locked_out_reason"].as_str().unwrap_or("");
    assert!(
        why.contains("no account in the reference hive") || why.contains("not exercised"),
        "a bit no evidence exercised is not asserted either way: {why}"
    );
}

/// A bit outside the four this build names is reported as a number.
#[test]
fn an_account_control_bit_this_build_does_not_name_is_reported_as_a_number() {
    let mut bytes = F_1000;
    // 0x0800 — a bit no account in the reference hive sets.
    bytes[0x39] = 0x08;
    let f = FValue::parse(&bytes).expect("parse");
    let j = LocalAccount::new("000003E8", Some(f), None, 0).to_json();
    let unnamed = j["account_control_unnamed_bits"].as_str().unwrap_or("");
    assert!(
        unnamed.contains("0x0800"),
        "an unnamed bit is published as the bit it is: {unnamed}"
    );
}

/// An `F` that is not 80 bytes is not parsed at fixed offsets.
#[test]
fn an_f_value_of_the_wrong_length_is_refused_rather_than_read_at_a_guess() {
    for len in [0usize, 1, 0x4F, 0x51, 0x100] {
        let bytes = vec![0u8; len];
        assert!(
            FValue::parse(&bytes).is_none(),
            "an {len}-byte F must not be read at the 80-byte offsets"
        );
    }
    // And the record says so rather than falling silent.
    let j = LocalAccount::new("000003E8", None, Some("Preston"), 72).to_json();
    assert!(j["rid"].is_number(), "the key name still gives the RID");
    assert!(j["last_logon"].is_null());
    let why = j["f_value_note"].as_str().unwrap_or("");
    assert!(
        why.contains("72") && why.contains("80"),
        "both lengths, so the reader knows what was there: {why}"
    );
}

/// The fields this evidence could not establish are named as not read.
#[test]
fn the_fields_this_evidence_could_not_establish_are_named_and_not_published() {
    let f = FValue::parse(&F_500).expect("parse");
    let j = LocalAccount::new("000001F4", Some(f), None, 0).to_json();
    for absent in [
        "account_expires",
        "last_incorrect_password",
        "failed_login_count",
        "country_code",
        "codepage",
    ] {
        assert!(
            j.get(absent).is_none(),
            "{absent} is not established by this evidence and must not be a field"
        );
    }
    let not_read: Vec<&str> = j["f_fields_not_read"]
        .as_array()
        .expect("the list is the record of it")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        not_read.iter().any(|s| s.contains("expir")),
        "got {not_read:?}"
    );
    assert!(
        not_read
            .iter()
            .any(|s| s.contains("0x28") || s.contains("incorrect")),
        "got {not_read:?}"
    );
}

// --- The V value -----------------------------------------------------------
//
// `V` opens with an array of 12-byte descriptors — offset, length, and a third
// word — whose offsets are relative to `V + 0xCC`. Measured slot-1 triples:
// RID 500 (off 0x00bc, len 26), RID 501 (off 0x00b0, len 10), RID 1000
// (off 0x00bc, len 14), resolving to V+0x188, V+0x17C and V+0x188.

/// Build a `V` value with the descriptor array this hive has, so the tests are
/// driven by the real shape rather than by a convenient one.
fn v_with(slots: &[(usize, &[u8])]) -> Vec<u8> {
    let header = V_DESCRIPTOR_COUNT * V_DESCRIPTOR_BYTES;
    let mut payload: Vec<u8> = Vec::new();
    let mut triples = vec![(0u32, 0u32, 0u32); V_DESCRIPTOR_COUNT];
    for (slot, bytes) in slots {
        triples[*slot] = (payload.len() as u32, bytes.len() as u32, 0);
        payload.extend_from_slice(bytes);
    }
    let mut out = vec![0u8; header];
    debug_assert_eq!(header, V_PAYLOAD_BASE, "the payload begins at 0xCC");
    for (i, (off, len, third)) in triples.iter().enumerate() {
        let at = i * V_DESCRIPTOR_BYTES;
        out[at..at + 4].copy_from_slice(&off.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&len.to_le_bytes());
        out[at + 8..at + 12].copy_from_slice(&third.to_le_bytes());
    }
    out.extend_from_slice(&payload);
    out
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// The username comes out of slot 1, and matches the `Names` key.
#[test]
fn the_username_decodes_from_the_v_value_and_agrees_with_the_names_key() {
    let v = v_with(&[(V_SLOT_USERNAME, &utf16("Administrator"))]);
    let parsed = VValue::parse(&v).expect("a V value of the real shape parses");
    assert_eq!(parsed.username.as_deref(), Some("Administrator"));
    // 26 bytes for thirteen UTF-16 characters, which is the measured length.
    assert_eq!(parsed.descriptors[V_SLOT_USERNAME].length, 26);
}

/// **The trap the real hive sets.** A zero-length descriptor still carries a
/// live offset, and on this hive slots 2 and 3 share it.
///
/// Measured: RID 500 slot 2 is `(off 0x00d8, len 0)` and slot 3 is
/// `(off 0x00d8, len 108)`. Reading to a NUL instead of honouring the length
/// prints "Built-in account for administering the computer/domain" as
/// Administrator's **full name**. On RID 1000 both slots are `(off 0x00cc,
/// len 0)`, which resolves to the all-`0xFF` logon-hours bitmap.
#[test]
fn a_zero_length_descriptor_is_an_absence_and_not_the_next_strings_bytes() {
    let comment = utf16("Built-in account for administering the computer/domain");
    let mut v = v_with(&[(V_SLOT_COMMENT, &comment)]);
    // Point slot 2 at the same payload offset with a zero length, exactly as
    // the hive does.
    let at = V_SLOT_FULL_NAME * V_DESCRIPTOR_BYTES;
    let shared_offset = u32::from_le_bytes(
        v[V_SLOT_COMMENT * V_DESCRIPTOR_BYTES..][..4]
            .try_into()
            .expect("four bytes"),
    );
    v[at..at + 4].copy_from_slice(&shared_offset.to_le_bytes());
    v[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());

    let parsed = VValue::parse(&v).expect("parse");
    assert_eq!(
        parsed.full_name, None,
        "a zero length is an absence, whatever its offset points at"
    );
    assert_eq!(
        parsed.comment.as_deref(),
        Some("Built-in account for administering the computer/domain")
    );
}

/// A descriptor whose offset and length run past the value is refused, and
/// named, rather than read out of whatever follows.
#[test]
fn a_descriptor_running_past_the_value_is_refused_and_named() {
    let mut v = v_with(&[(V_SLOT_USERNAME, &utf16("Preston"))]);
    let at = V_SLOT_USERNAME * V_DESCRIPTOR_BYTES;
    v[at + 4..at + 8].copy_from_slice(&4096u32.to_le_bytes());
    let parsed = VValue::parse(&v).expect("the array still parses");
    assert_eq!(parsed.username, None);
    assert!(
        parsed
            .out_of_bounds
            .iter()
            .any(|s| s.contains("1") && s.contains("4096")),
        "the refusal names the slot and the length: {:?}",
        parsed.out_of_bounds
    );
}

/// An odd-length string is not read as UTF-16 by dropping a byte.
#[test]
fn a_string_descriptor_of_odd_length_is_not_silently_truncated() {
    let mut bytes = utf16("Guest");
    bytes.push(0x41);
    let v = v_with(&[(V_SLOT_USERNAME, &bytes)]);
    let parsed = VValue::parse(&v).expect("parse");
    assert_eq!(parsed.username, None);
    assert!(
        parsed
            .out_of_bounds
            .iter()
            .any(|s| s.contains("odd") || s.contains("11")),
        "got {:?}",
        parsed.out_of_bounds
    );
}

/// Whether hash material is stored is reported; the hash is not.
///
/// Measured: slot 14 is 20 bytes (a 4-byte header and 16 bytes of material) on
/// RIDs 500 and 1000, and **4 bytes — header only — on Guest**, which is the
/// account with no password. Slot 13 is 4 bytes on all three.
#[test]
fn the_presence_of_stored_hash_material_is_reported_and_the_hash_is_not() {
    let populated = v_with(&[(V_SLOT_NT_HASH, &[0u8; 20])]);
    let parsed = VValue::parse(&populated).expect("parse");
    assert_eq!(parsed.nt_hash_material_present, Some(true));

    let header_only = v_with(&[(V_SLOT_NT_HASH, &[0u8; 4])]);
    let parsed = VValue::parse(&header_only).expect("parse");
    assert_eq!(
        parsed.nt_hash_material_present,
        Some(false),
        "four bytes is the header and no hash -- Guest's measured length"
    );

    // And the record never carries the bytes.
    let f = FValue::parse(&F_500).expect("parse");
    let j = LocalAccount::new("000001F4", Some(f), Some("Administrator"), 0)
        .with_v(VValue::parse(&v_with(&[(V_SLOT_NT_HASH, &[0xAB; 20])])).expect("parse"))
        .to_json();
    assert_eq!(j["stored_password_hash_present"], serde_json::json!(true));
    let rendered = serde_json::to_string(&j).expect("serialise");
    assert!(
        !rendered.to_lowercase().contains("abababab"),
        "no hash material may reach the record: {rendered}"
    );
}

/// A `V` too short to hold its own descriptor array is refused.
#[test]
fn a_v_value_too_short_for_its_descriptor_array_is_refused() {
    for len in [0usize, 1, V_PAYLOAD_BASE - 1] {
        assert!(
            VValue::parse(&vec![0u8; len]).is_none(),
            "a {len}-byte V cannot hold {V_DESCRIPTOR_COUNT} descriptors"
        );
    }
    // Exactly the array and no payload is legitimate: every slot is empty.
    let parsed = VValue::parse(&vec![0u8; V_PAYLOAD_BASE]).expect("an empty-but-valid V");
    assert_eq!(parsed.username, None);
    assert!(parsed.out_of_bounds.is_empty());
}

/// The descriptor census is on the record, so a slot this build does not name
/// is visible rather than hidden.
#[test]
fn every_descriptor_is_accounted_for_on_the_record() {
    let v = v_with(&[
        (V_SLOT_USERNAME, &utf16("Preston")),
        // Slot 11, the logon-hours bitmap: 21 bytes, all hours permitted.
        (11, &[0xFFu8; 21]),
    ]);
    let f = FValue::parse(&F_1000).expect("parse");
    let j = LocalAccount::new("000003E8", Some(f), Some("Preston"), 0)
        .with_v(VValue::parse(&v).expect("parse"))
        .to_json();
    let census = j["v_descriptors"].as_array().expect("the census");
    assert_eq!(
        census.len(),
        V_DESCRIPTOR_COUNT,
        "all {V_DESCRIPTOR_COUNT}, populated or not"
    );
    let slot11 = &census[11];
    assert_eq!(slot11["slot"], serde_json::json!(11));
    assert_eq!(slot11["length"], serde_json::json!(21));
    assert_eq!(
        census[2]["length"],
        serde_json::json!(0),
        "an empty slot is listed with its zero, not dropped"
    );
}

// --- End to end, on the real hive ------------------------------------------

/// The whole parser over `reference/plaso/test_data/SAM`, against the answers
/// measured off the hive.
///
/// Corpus-gated: `reference/` is in `.gitignore`, so this file is on the
/// machine that measured it and absent from a fresh clone.
#[test]
fn the_real_sam_hive_yields_three_accounts_with_their_rids_names_and_times() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SAM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SAM", bytes);
    let accounts: Vec<&serde_json::Value> =
        all.iter().filter(|r| r["type"] == "LocalAccount").collect();
    assert_eq!(
        accounts.len(),
        3,
        "three accounts, which plaso's own test for this file independently asserts: {:?}",
        accounts
            .iter()
            .map(|a| a["username"].clone())
            .collect::<Vec<_>>()
    );

    let by_rid = |rid: u64| {
        accounts
            .iter()
            .find(|a| a["rid"] == serde_json::json!(rid))
            .unwrap_or_else(|| panic!("RID {rid} is in this hive"))
    };

    let admin = by_rid(500);
    assert_eq!(admin["username"], "Administrator");
    assert_eq!(
        admin["username_basis"], "the V value's name descriptor and the Users\\Names key agree",
        "both routes are read, and their agreement is worth stating"
    );
    assert!(
        admin["last_logon"]
            .as_str()
            .unwrap_or("")
            .starts_with("2010-11-20T21:48:12.569244"),
        "got {:?}",
        admin["last_logon"]
    );
    assert!(
        admin["last_password_set"]
            .as_str()
            .unwrap_or("")
            .starts_with("2010-11-20T21:56:34.743687"),
        "got {:?}",
        admin["last_password_set"]
    );
    assert_eq!(admin["login_count"], serde_json::json!(6));
    assert_eq!(admin["account_enabled"], serde_json::json!(false));
    assert_eq!(admin["primary_group_rid"], serde_json::json!(513));
    assert_eq!(
        admin["comment"],
        "Built-in account for administering the computer/domain"
    );
    assert_eq!(
        admin["stored_password_hash_present"],
        serde_json::json!(true)
    );

    // Guest: the account that has never been used, and three fields agree.
    let guest = by_rid(501);
    assert_eq!(guest["username"], "Guest");
    assert!(
        guest["last_logon"].is_null(),
        "got {:?} -- a zero is not 1601",
        guest["last_logon"]
    );
    assert!(guest["last_password_set"].is_null());
    assert_eq!(guest["login_count"], serde_json::json!(0));
    assert_eq!(guest["password_not_required"], serde_json::json!(true));
    assert_eq!(
        guest["stored_password_hash_present"],
        serde_json::json!(false),
        "four bytes of blob is the header and no hash"
    );

    let preston = by_rid(1000);
    assert_eq!(preston["username"], "Preston");
    assert!(
        preston["last_logon"]
            .as_str()
            .unwrap_or("")
            .starts_with("2014-09-30T02:59:34.316692"),
        "got {:?}",
        preston["last_logon"]
    );
    assert_eq!(preston["login_count"], serde_json::json!(4));
    assert_eq!(preston["account_enabled"], serde_json::json!(true));
    assert!(
        preston["comment"].is_null(),
        "this account has no comment, and an absence is not \"\": {:?}",
        preston["comment"]
    );

    // **The trap.** No account in this hive has a full name, and slots 2 and 3
    // share an offset on Administrator, so a reader that ignores the declared
    // length prints the comment as the full name.
    for a in &accounts {
        assert!(
            a["full_name"].is_null(),
            "{:?} has no full name in this hive, and got {:?} -- a zero-length descriptor's \
             offset points at the next payload",
            a["username"],
            a["full_name"]
        );
    }

    // And no account renders a sentinel as a date.
    for a in &accounts {
        for field in ["last_logon", "last_password_set", "key_last_written"] {
            if let Some(t) = a[field].as_str() {
                assert!(t.starts_with("20"), "{:?}.{field} is {t:?}", a["username"]);
            }
        }
        assert!(
            a["account_expires"].is_null(),
            "the expiry slot is not established by this evidence and must not be published"
        );
    }
}

/// And the `SYSTEM` hive yields no accounts, rather than an empty answer that
/// reads like one.
#[test]
fn a_hive_with_no_sam_accounts_emits_no_account_records() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    assert!(
        !all.iter().any(|r| r["type"] == "LocalAccount"),
        "a SYSTEM hive holds no SAM accounts and must claim none"
    );
}
