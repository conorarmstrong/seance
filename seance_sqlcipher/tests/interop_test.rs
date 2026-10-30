//! Interoperability against a database written by SQLCipher itself.
//!
//! # Why this file exists
//!
//! The unit tests round-trip this crate's own `encrypt_for_test` through its
//! own `decrypt`, which proves the two agree with each other and nothing more.
//! Both were written from one reading of upstream's `sqlcipher.c`, so a single
//! misreading — the HMAC salt mask, the iteration count, whether the IV is
//! inside the authenticated span, whether the page number is little-endian —
//! would be baked into both halves and every one of those tests would still
//! pass.
//!
//! That is precisely the trap the crate documentation warned about when it
//! declined to implement the HMAC by guesswork: *"a wrong change to the cipher
//! framing silently corrupts decryption"*. The only way out is a database this
//! project did not write.
//!
//! # The fixture
//!
//! `fixtures/sqlcipher3_sha1_1024.db` was produced by **SQLCipher 4.6.1 built
//! from upstream source**, with the SQLCipher-3-era parameters this crate
//! supports:
//!
//! ```text
//! PRAGMA key = 'correct horse';
//! PRAGMA cipher_page_size = 1024;
//! PRAGMA kdf_iter = 4000;
//! PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
//! PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;
//! CREATE TABLE message(id INTEGER PRIMARY KEY, body TEXT);
//! INSERT INTO message(body) VALUES('the quick brown fox'),('second row'),('third row');
//! ```
//!
//! It is 2 KB of synthetic data with no provenance concerns, and it is the only
//! thing in this crate's test suite that can fail if the framing is
//! misunderstood.

use seance_sqlcipher::{decrypt_with_provenance, SqlCipherConfig, INTEGRITY_VERIFIED};

/// The parameters the fixture was written with.
fn fixture_config() -> SqlCipherConfig {
    SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 4000,
        use_hmac: true,
    }
}

const PASSPHRASE: &[u8] = b"correct horse";
const FIXTURE: &[u8] = include_bytes!("fixtures/sqlcipher3_sha1_1024.db");

/// **The test that makes the HMAC implementation trustworthy.**
///
/// Every tag in this file was computed by SQLCipher's own OpenSSL-backed
/// provider. Verifying them here proves this crate's HMAC key derivation
/// (encryption key as the password, database salt XOR 0x3a as the salt, two
/// iterations) and its authenticated span (ciphertext, then IV, then the 1-based
/// page number little-endian) match upstream byte for byte — none of which the
/// round-trip tests can establish.
#[test]
fn a_real_sqlcipher_database_decrypts_and_authenticates() {
    let result =
        decrypt_with_provenance(FIXTURE, PASSPHRASE, &fixture_config()).expect("the key is right");

    assert_eq!(result.pages, 2);
    assert_eq!(
        &result.plaintext[..16],
        b"SQLite format 3\0",
        "the decrypted first page must be a SQLite header"
    );
    assert!(
        String::from_utf8_lossy(&result.plaintext).contains("the quick brown fox"),
        "the row written through sqlcipher must come back out"
    );

    assert!(
        result.integrity_verified,
        "tags written by SQLCipher itself must verify: {}",
        result.integrity_statement
    );
    assert!(result.failed_pages.is_empty());
    assert_eq!(result.integrity_statement, INTEGRITY_VERIFIED);
}

/// Tampering with a genuine SQLCipher page is caught.
///
/// The counterweight: if the verifier accepted everything, the test above would
/// pass just as happily with the comparison removed.
#[test]
fn a_tampered_byte_in_a_real_database_is_caught() {
    let mut tampered = FIXTURE.to_vec();
    // Byte 600 is inside page 1's ciphertext (which begins at 16 and runs to
    // 1024 - 48 = 976).
    tampered[600] ^= 0x01;

    let result = decrypt_with_provenance(&tampered, PASSPHRASE, &fixture_config());

    // Flipping a ciphertext bit may also break the SQLite header check, in
    // which case decryption declines outright. Either outcome is acceptable;
    // what must never happen is a result reporting the page as authenticated.
    if let Some(result) = result {
        assert!(
            !result.integrity_verified,
            "an altered page must not be reported as sound"
        );
        assert!(result.failed_pages.contains(&1));
    }
}

/// Tampering with page 2 is caught, and page 1 still authenticates.
///
/// Page 2 has no salt offset, so it exercises the `content_off == 0` branch of
/// the authenticated span — the one page 1 cannot cover.
#[test]
fn a_tampered_second_page_is_named_and_the_first_still_passes() {
    let mut tampered = FIXTURE.to_vec();
    tampered[1024 + 100] ^= 0x01;

    let result = decrypt_with_provenance(&tampered, PASSPHRASE, &fixture_config())
        .expect("page 1 is untouched, so the header check still passes");

    assert!(!result.integrity_verified);
    assert_eq!(
        result.failed_pages,
        vec![2],
        "only the altered page may be named"
    );
}

/// The wrong passphrase is refused rather than yielding plausible rows.
#[test]
fn the_wrong_passphrase_is_refused_on_a_real_database() {
    assert!(
        decrypt_with_provenance(FIXTURE, b"wrong horse", &fixture_config()).is_none(),
        "a wrong key must fail the header check, not return garbage as evidence"
    );
}
