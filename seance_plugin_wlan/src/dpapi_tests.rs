//! What a DPAPI blob says about itself, and what it refuses to say.

use super::test_support::{blob, MASTER_KEY};
use super::*;

/// **The master key's GUID is the point.** It names the file an examiner has
/// to fetch from elsewhere in the image, and the statement says which one and
/// what else is needed.
#[test]
fn the_master_key_guid_and_the_description_are_read_from_the_clear_fields() {
    let key = MASTER_KEY;
    let bytes = blob(key, "wifi passphrase", &[0x11; 48]);
    let parsed = parse(&bytes).expect("a DPAPI blob");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.master_key_guid, key);
    assert_eq!(parsed.description, "wifi passphrase");
    assert_eq!(parsed.ciphertext_bytes, 48);
    assert_eq!(parsed.blob_bytes, bytes.len());
    let statement = parsed.statement();
    assert!(statement.contains(key), "{statement}");
    assert!(statement.contains("does NOT decrypt"), "{statement}");
    assert!(statement.contains("SYSTEM hive"), "{statement}");
    assert!(statement.contains("DPAPI_SYSTEM"), "{statement}");
    assert_eq!(parsed.to_json()["decrypted"], serde_json::json!(false));
}

/// Windows protects a wireless key with no description at all. An empty one is
/// read as empty rather than making the blob unreadable.
#[test]
fn a_blob_with_no_description_is_still_read() {
    let bytes = blob("11111111-2222-3333-4444-555555555555", "", &[0x22; 32]);
    let parsed = parse(&bytes).expect("a DPAPI blob");
    assert_eq!(parsed.description, "");
    assert_eq!(parsed.ciphertext_bytes, 32);
}

/// **The provider GUID is the gate.** Without it, any hex string of the right
/// length would be read as a blob and its "master key GUID" would be sixteen
/// bytes of something else.
#[test]
fn bytes_that_are_not_a_dpapi_blob_are_refused() {
    let mut bytes = blob("11111111-2222-3333-4444-555555555555", "", &[0x22; 32]);
    assert!(looks_like_dpapi(&bytes));
    bytes[8] ^= 0xff;
    assert!(!looks_like_dpapi(&bytes));
    assert!(parse(&bytes).is_none());

    // A version this build does not know is a different structure.
    let mut wrong_version = blob("11111111-2222-3333-4444-555555555555", "", &[0x22; 32]);
    wrong_version[0] = 2;
    assert!(parse(&wrong_version).is_none());

    assert!(parse(b"").is_none());
    assert!(parse(b"hunter2").is_none());
    assert!(!looks_like_dpapi(b"hunter2"));
}

/// A blob cut short is refused rather than read as far as it goes: a length
/// field that runs past the end means the fields after it are not where they
/// are being read from.
#[test]
fn a_truncated_blob_is_refused_rather_than_partly_read() {
    let bytes = blob("11111111-2222-3333-4444-555555555555", "x", &[0x22; 64]);
    for cut in [20, 40, 60, bytes.len() - 1] {
        assert!(
            parse(&bytes[..cut]).is_none(),
            "a blob cut at {cut} bytes must be refused"
        );
    }
}

/// A declared length no blob could hold is refused before it is trusted, and
/// nothing overflows on the way.
#[test]
fn a_hostile_length_is_refused_not_trusted() {
    let mut bytes = blob("11111111-2222-3333-4444-555555555555", "", &[0x22; 32]);
    // The description length, at offset 4 + 16 + 4 + 16 + 4 = 44.
    bytes[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse(&bytes).is_none());
    bytes[44..48].copy_from_slice(&(u32::MAX - 3).to_le_bytes());
    assert!(parse(&bytes).is_none());
}

/// The hex Windows writes, and the things that are not it.
#[test]
fn key_material_is_read_as_hex_or_refused() {
    assert_eq!(from_hex("01000000").expect("hex"), vec![1, 0, 0, 0]);
    assert_eq!(
        from_hex("DEADBEEF").expect("hex"),
        vec![0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(
        from_hex("de ad\nbe ef").expect("hex"),
        vec![0xde, 0xad, 0xbe, 0xef],
        "a document through an editor may carry whitespace"
    );
    // A passphrase is not hex, and must not be read as a blob.
    assert!(from_hex("hunter2").is_none());
    assert!(from_hex("").is_none());
    assert!(
        from_hex("abc").is_none(),
        "an odd number of digits is not hex"
    );
    // A passphrase that happens to be valid hex decodes -- and is then
    // refused as a blob by the provider GUID, which is the gate that matters.
    let decoded = from_hex("deadbeefdeadbeef").expect("hex");
    assert!(!looks_like_dpapi(&decoded));
}

/// The master-key file the statement sends an examiner to is the one Windows
/// wrote. On LoneWolf (`WLAN-1` in `documentation/VALIDATION.md`) the profile's
/// blob names master key `1fbfafc4-…`, and that file is
/// `Windows/System32/Microsoft/Protect/S-1-5-18/User/1fbfafc4-8882-463c-89ee-65cbdc18313a`
/// (inode 90938) — under `User`, not beside `Preferred` one level up where the
/// statement pointed. An examiner told the wrong directory finds no such file.
#[test]
fn the_statement_names_the_master_key_file_where_windows_keeps_it() {
    let key = "1fbfafc4-8882-463c-89ee-65cbdc18313a";
    let parsed = parse(&blob(key, "", &[0x33; 16])).expect("a DPAPI blob");
    let statement = parsed.statement();
    assert!(
        statement.contains(&format!(
            r"Windows\System32\Microsoft\Protect\S-1-5-18\User\{key}"
        )),
        "{statement}"
    );
}
