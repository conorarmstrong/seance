use super::*;

/// PBKDF2-HMAC-SHA1 known-answer vector from RFC 6070, confirming the primitive
/// the key derivation is built on.
#[test]
fn pbkdf2_hmac_sha1_rfc6070() {
    let mut out = [0u8; 20];
    pbkdf2::pbkdf2::<super::HmacSha1>(b"password", b"salt", 1, &mut out);
    let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "0c60c80f961f0e71f3a9b524af6012062fe037a6");

    let mut out2 = [0u8; 20];
    pbkdf2::pbkdf2::<super::HmacSha1>(b"password", b"salt", 2, &mut out2);
    let hex2: String = out2.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
}

/// WeChat passphrase = first 7 hex chars of MD5(imei+uin). MD5("") is a known
/// constant, so this checks the derivation without circularity.
#[test]
fn wechat_passphrase_is_md5_prefix() {
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    assert_eq!(wechat_passphrase("", ""), b"d41d8cd");
    // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
    assert_eq!(wechat_passphrase("a", "bc"), b"9001509");
}

/// Build plaintext SQLite-shaped bytes (valid header fields, zeroed reserve).
fn make_plaintext(pages: usize, cfg: &SqlCipherConfig) -> Vec<u8> {
    let ps = cfg.page_size;
    let reserve = if cfg.use_hmac { 48 } else { 16 };
    let usable = ps - reserve;
    let mut v = vec![0u8; pages * ps];
    v[0..16].copy_from_slice(b"SQLite format 3\0");
    v[16..18].copy_from_slice(&(ps as u16).to_be_bytes()); // page-size field
    v[20] = reserve as u8; // reserved bytes per page
    for i in 0..pages {
        let start = if i == 0 { 21 } else { 0 };
        for j in start..usable {
            v[i * ps + j] = ((i * 7 + j * 13) & 0xff) as u8;
        }
    }
    v
}

#[test]
fn round_trip_recovers_plaintext_with_hmac_reserve() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8, // fast for the test; the decrypt path is identical
        use_hmac: true,
    };
    let plain = make_plaintext(3, &cfg);
    let salt = [0x11u8; 16];
    let pass = b"correct horse";

    let enc = encrypt_for_test(&plain, pass, &salt, &cfg);
    // The encrypted file starts with the salt, not the SQLite header.
    assert_eq!(&enc[0..16], &salt);
    assert_ne!(&enc[0..16], b"SQLite format 3\0");

    let dec = decrypt(&enc, pass, &cfg).expect("decrypts with the right passphrase");
    assert_eq!(dec, plain, "round-trip must recover the plaintext exactly");
}

#[test]
fn wrong_passphrase_is_rejected_not_silently_wrong() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: true,
    };
    let plain = make_plaintext(2, &cfg);
    let enc = encrypt_for_test(&plain, b"right-key", &[0x22u8; 16], &cfg);
    // A wrong key yields a header whose page-size field won't match -> None.
    assert!(decrypt(&enc, b"wrong-key", &cfg).is_none());
}

#[test]
fn no_hmac_reserve_round_trips() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: false, // reserve = 16 (IV only)
    };
    let plain = make_plaintext(2, &cfg);
    let enc = encrypt_for_test(&plain, b"k", &[0x33u8; 16], &cfg);
    assert_eq!(decrypt(&enc, b"k", &cfg).unwrap(), plain);
}

#[test]
fn non_page_aligned_tail_fails_closed() {
    // A truncated ciphertext with a partial trailing page must not silently
    // decrypt to a database missing its last page (BUG-174).
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: false,
    };
    let plain = make_plaintext(3, &cfg);
    let mut enc = encrypt_for_test(&plain, b"k", &[0x44u8; 16], &cfg);
    // The intact ciphertext decrypts.
    assert!(decrypt(&enc, b"k", &cfg).is_some());
    // Append a stray partial page: the length is no longer a page multiple.
    enc.extend_from_slice(&[0u8; 37]);
    assert!(
        decrypt(&enc, b"k", &cfg).is_none(),
        "a non-page-aligned tail must fail closed"
    );
    // Truncating a page mid-way is likewise rejected.
    let truncated = &enc[..enc.len() - 37 - 100];
    assert!(decrypt(truncated, b"k", &cfg).is_none());
}

/// Every page is authenticated, and the result says exactly that.
///
/// What an examiner learns: whether a recovered message can be relied on to be
/// the message that was stored. Before BUG-012 was closed the answer was "no,
/// and here is the sentence saying so"; now every page's HMAC-SHA1 is
/// recomputed over its ciphertext, IV and page number and compared with the tag
/// the page carries.
#[test]
fn a_clean_database_authenticates_every_page() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: true,
    };
    let plain = make_plaintext(3, &cfg);
    let salt = [0x22u8; 16];
    let pass = b"correct horse";
    let enc = encrypt_for_test(&plain, pass, &salt, &cfg);

    let result = decrypt_with_provenance(&enc, pass, &cfg).expect("the key is right");
    assert_eq!(result.plaintext, plain);
    assert_eq!(result.pages, 3);
    assert!(
        result.integrity_verified,
        "an untampered database must authenticate: {}",
        result.integrity_statement
    );
    assert!(result.failed_pages.is_empty());
    assert_eq!(result.integrity_statement, INTEGRITY_VERIFIED);

    assert_eq!(decrypt(&enc, pass, &cfg), Some(plain));
}

/// A database written without HMACs cannot be verified, and that is a different
/// statement from having been verified and failed.
///
/// The distinction matters in a report: "there was nothing to check" is a fact
/// about the evidence, "it was checked and failed" is a finding about it.
#[test]
fn a_database_without_hmacs_says_there_was_nothing_to_check() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: false,
    };
    let plain = make_plaintext(2, &cfg);
    let salt = [0x77u8; 16];
    let enc = encrypt_for_test(&plain, b"k", &salt, &cfg);

    let result = decrypt_with_provenance(&enc, b"k", &cfg).expect("decrypts");
    assert!(
        !result.integrity_verified,
        "absence of HMACs must never read as a passed check"
    );
    assert!(
        result.failed_pages.is_empty(),
        "no page failed; there was simply nothing to verify"
    );
    assert_eq!(result.integrity_statement, NO_HMACS_PRESENT);
}

/// **The regression for BUG-012.** A page altered after encryption is caught,
/// named, and refused the description "sound".
///
/// This test previously asserted the opposite — that a tampered page "is
/// returned without complaint" — because that was true, and pinning it was the
/// honest thing to do while it was. It now pins the fix.
#[test]
fn a_tampered_page_is_detected_and_named() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: true,
    };
    let plain = make_plaintext(3, &cfg);
    let salt = [0x33u8; 16];
    let pass = b"correct horse";
    let mut enc = encrypt_for_test(&plain, pass, &salt, &cfg);

    // Flip a bit deep inside page 2's ciphertext.
    enc[cfg.page_size + 64] ^= 0x01;

    let result = decrypt_with_provenance(&enc, pass, &cfg)
        .expect("page 1's header still matches, so decryption proceeds");

    assert!(!result.integrity_verified);
    assert_eq!(
        result.failed_pages,
        vec![2],
        "the failing page must be named, not merely counted: an examiner has to \
         know which rows are affected"
    );
    assert!(
        result.integrity_statement.contains("page(s) 2"),
        "the statement must name the page: {}",
        result.integrity_statement
    );
    // The plaintext is still handed back. Withholding it would deny an examiner
    // evidence that may matter; the record simply must not call it sound.
    assert_ne!(result.plaintext, plain);
    assert_eq!(result.plaintext.len(), plain.len());
}

/// Tampering with the IV is caught, not just tampering with the ciphertext.
///
/// The IV is inside the authenticated span precisely so it cannot be swapped:
/// changing it changes the plaintext of the whole page without touching a byte
/// of ciphertext.
#[test]
fn a_swapped_initialisation_vector_is_detected() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: true,
    };
    let plain = make_plaintext(3, &cfg);
    let salt = [0x55u8; 16];
    let mut enc = encrypt_for_test(&plain, b"k", &salt, &cfg);

    // The IV sits immediately after the ciphertext, at `usable`.
    let usable = cfg.page_size - 48; // IV(16) + HMAC(20) rounded up to 48
    enc[cfg.page_size + usable] ^= 0xFF;

    let result = decrypt_with_provenance(&enc, b"k", &cfg).expect("page 1 still decrypts");
    assert_eq!(result.failed_pages, vec![2]);
}

/// Two otherwise-valid pages exchanged is caught, because the page number is
/// authenticated.
///
/// This is the attack the ciphertext-only HMAC would miss entirely: both pages
/// are genuine, both were written by the real key, and only their order is a
/// lie. Reordering a message store rewrites a conversation.
#[test]
fn two_resequenced_pages_are_detected() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: true,
    };
    let plain = make_plaintext(4, &cfg);
    let salt = [0x66u8; 16];
    let enc = encrypt_for_test(&plain, b"k", &salt, &cfg);

    // Swap pages 3 and 4 wholesale, tags and all.
    let ps = cfg.page_size;
    let mut swapped = enc.clone();
    swapped[2 * ps..3 * ps].copy_from_slice(&enc[3 * ps..4 * ps]);
    swapped[3 * ps..4 * ps].copy_from_slice(&enc[2 * ps..3 * ps]);

    let result = decrypt_with_provenance(&swapped, b"k", &cfg).expect("page 1 still decrypts");
    assert!(!result.integrity_verified);
    assert_eq!(
        result.failed_pages,
        vec![3, 4],
        "both moved pages must be flagged; each carries a tag bound to its old position"
    );
}

/// Page 1 is authenticated too, over the region that excludes the salt.
#[test]
fn tampering_with_page_one_is_detected() {
    let cfg = SqlCipherConfig {
        page_size: 1024,
        kdf_iter: 8,
        use_hmac: true,
    };
    let plain = make_plaintext(2, &cfg);
    let salt = [0x11u8; 16];
    let mut enc = encrypt_for_test(&plain, b"k", &salt, &cfg);

    // Byte 40 is inside page 1's ciphertext (which starts at 16).
    enc[40] ^= 0x02;

    let result = decrypt_with_provenance(&enc, b"k", &cfg);
    // Page 1's header check may or may not survive the flip; whichever happens,
    // what must NOT happen is a result that reports page 1 as authenticated.
    if let Some(result) = result {
        assert!(
            result.failed_pages.contains(&1),
            "page 1 was altered and must be flagged"
        );
        assert!(!result.integrity_verified);
    }
}

// ---------------------------------------------------------------------------
// SQLCipher 4, raw key (HUNT-183)
// ---------------------------------------------------------------------------
//
// The encryptor below is written independently of the decryptor, straight from
// SQLCipher 4's framing: a raw 32-byte key used as the AES key with no KDF, the
// HMAC key `PBKDF2-HMAC-SHA512(key, salt ^ 0x3a, 2, 32)`, a tag of HMAC-SHA512
// over `ciphertext || IV || page_number_le32`, and an 80-byte reserve (16 IV +
// 64 tag). What makes the decryptor trustworthy is not these tests — it is
// `tests/signal_ios_real_store.rs`, which reads a store Signal for iOS wrote.

mod v4 {
    use super::super::*;
    use cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
    use hmac::Mac;
    use sha2::Sha512;

    const KEY: [u8; 32] = [0x5c; 32];
    const SALT: [u8; 16] = [0xa7; 16];
    const RESERVE: usize = 80;

    fn spec(key: &[u8; 32], salt: &[u8; 16]) -> RawKeySpec {
        let mut v = key.to_vec();
        v.extend_from_slice(salt);
        RawKeySpec::from_bytes(&v).expect("48 bytes is a key spec")
    }

    /// A SQLite database shaped like the one Signal for iOS writes: 4096-byte
    /// pages, WAL mode (read/write versions 2), 80 reserved bytes per page, a
    /// header SQLite itself would accept — including the 20 bytes at 72..92
    /// that SQLite requires to be zero — and non-trivial content on every page.
    pub(super) fn signal_shaped_plaintext(pages: usize) -> Vec<u8> {
        let ps = 4096;
        let usable = ps - RESERVE;
        let mut v = vec![0u8; pages * ps];
        for i in 0..pages {
            for j in 0..usable {
                v[i * ps + j] = ((i * 31 + j * 7 + 3) & 0xff) as u8;
            }
        }
        v[0..16].copy_from_slice(b"SQLite format 3\0");
        v[16..18].copy_from_slice(&4096u16.to_be_bytes());
        v[18] = 2;
        v[19] = 2;
        v[20] = RESERVE as u8;
        v[21] = 64;
        v[22] = 32;
        v[23] = 32;
        v[24..28].copy_from_slice(&2u32.to_be_bytes());
        v[28..32].copy_from_slice(&(pages as u32).to_be_bytes());
        v[32..72].fill(0);
        v[44..48].copy_from_slice(&4u32.to_be_bytes()); // schema format 4
        v[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8
        v[72..92].fill(0);
        v
    }

    fn hmac_key(key: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
        let masked: Vec<u8> = salt.iter().map(|b| b ^ 0x3a).collect();
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha512>>(key, &masked, 2, &mut out);
        out
    }

    /// One page encrypted the way SQLCipher 4 encrypts it. `header` is the
    /// number of leading bytes of page 1 that are not ciphertext.
    fn encrypt_page(
        plain_page: &[u8],
        page_number: u32,
        key: &[u8; 32],
        salt: &[u8; 16],
        header: usize,
        salt_in_file: bool,
        iv_seed: u8,
    ) -> Vec<u8> {
        let ps = plain_page.len();
        let usable = ps - RESERVE;
        let off = if page_number == 1 { header } else { 0 };
        let mut out = vec![0u8; ps];
        if page_number == 1 {
            if salt_in_file {
                out[0..16].copy_from_slice(salt);
            } else {
                out[0..header].copy_from_slice(&plain_page[0..header]);
            }
        }
        let mut iv = [iv_seed; 16];
        iv[0..4].copy_from_slice(&page_number.to_le_bytes());
        let mut ct = vec![0u8; usable - off];
        cbc::Encryptor::<aes::Aes256>::new(key.into(), &iv.into())
            .encrypt_padded_b2b_mut::<NoPadding>(&plain_page[off..usable], &mut ct)
            .unwrap();
        out[off..usable].copy_from_slice(&ct);
        out[usable..usable + 16].copy_from_slice(&iv);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&hmac_key(key, salt)).unwrap();
        mac.update(&out[off..usable + 16]);
        mac.update(&page_number.to_le_bytes());
        out[usable + 16..usable + 80].copy_from_slice(&mac.finalize().into_bytes());
        out
    }

    pub(super) fn encrypt_store(
        plain: &[u8],
        key: &[u8; 32],
        salt: &[u8; 16],
        header: usize,
    ) -> Vec<u8> {
        let salt_in_file = header == 0;
        let header = if salt_in_file { 16 } else { header };
        plain
            .chunks(4096)
            .enumerate()
            .flat_map(|(i, p)| encrypt_page(p, i as u32 + 1, key, salt, header, salt_in_file, 0x10))
            .collect()
    }

    // --- the key spec -------------------------------------------------------

    /// What an examiner types into the credential route (HUNT-227): the
    /// literal or the bare digits.
    #[test]
    fn a_key_spec_is_read_from_the_literal_or_bare_hex() {
        let hex: String = KEY
            .iter()
            .chain(SALT.iter())
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(RawKeySpec::from_text(&hex).unwrap().has_salt());
        assert!(RawKeySpec::from_text(&format!("  x'{hex}'\n"))
            .unwrap()
            .has_salt());
        assert_eq!(
            RawKeySpec::from_text("not hex").unwrap_err(),
            KeySpecError::NotAHexLiteral
        );
        assert_eq!(
            RawKeySpec::from_text("abcd").unwrap_err(),
            KeySpecError::WrongLength(2)
        );
    }

    #[test]
    fn a_48_byte_raw_key_spec_is_key_then_salt() {
        let s = spec(&KEY, &SALT);
        assert!(s.has_salt());
        let hex: String = KEY
            .iter()
            .chain(SALT.iter())
            .map(|b| format!("{b:02x}"))
            .collect();
        let lit = RawKeySpec::from_sql_literal(&format!("x'{hex}'")).expect("x'…' form");
        assert!(lit.has_salt());
        // Upper-case hex and the `X'…'` prefix are how SQLCipher prints it too.
        assert!(RawKeySpec::from_sql_literal(&format!("X'{}'", hex.to_uppercase())).is_ok());
        // A 32-byte raw key with the salt left to the file.
        assert!(!RawKeySpec::from_bytes(&KEY).unwrap().has_salt());
        assert_eq!(
            RawKeySpec::from_bytes(&[0u8; 47]).unwrap_err(),
            KeySpecError::WrongLength(47)
        );
        assert_eq!(
            RawKeySpec::from_sql_literal("correct horse").unwrap_err(),
            KeySpecError::NotAHexLiteral
        );
    }

    /// Key material never reaches a log through `Debug`.
    #[test]
    fn a_key_spec_never_prints_its_bytes() {
        let s = spec(&KEY, &SALT);
        let shown = format!("{s:?} {s:#?}");
        assert!(
            !shown.contains("5c"),
            "key bytes leaked into Debug: {shown}"
        );
        assert!(
            !shown.contains("92"),
            "key bytes leaked into Debug: {shown}"
        );
        assert!(
            !shown.contains("a7"),
            "salt bytes leaked into Debug: {shown}"
        );
        assert!(shown.contains("redacted"), "{shown}");
    }

    // --- the store ----------------------------------------------------------

    /// The shape Signal for iOS writes: raw key, 32-byte plaintext header,
    /// HMAC-SHA512. Before HUNT-183 this form was not decrypted at all.
    #[test]
    fn a_signal_ios_shaped_store_decrypts_under_its_raw_key_and_every_page_authenticates() {
        let plain = signal_shaped_plaintext(3);
        let enc = encrypt_store(&plain, &KEY, &SALT, 32);
        // The file's first 32 bytes are the plaintext header, as on the device.
        assert_eq!(&enc[0..16], b"SQLite format 3\0");
        assert_eq!(enc[20], 80);

        let d = decrypt_v4_raw_key(&enc, &spec(&KEY, &SALT), &SqlCipher4Config::signal_ios())
            .expect("the right raw key decrypts a SQLCipher 4 plaintext-header store");
        assert_eq!(d.plaintext, plain);
        assert_eq!(d.pages, 3);
        assert!(d.integrity_verified, "{}", d.integrity_statement);
        assert!(d.failed_pages.is_empty());
        assert_eq!(d.integrity_statement, INTEGRITY_VERIFIED_SHA512);
        assert!(INTEGRITY_VERIFIED_SHA512.contains("HMAC-SHA512"));
    }

    /// A plaintext header proves nothing about the key — it was never
    /// encrypted — so a wrong key must be caught behind it.
    #[test]
    fn a_wrong_raw_key_is_refused_even_though_the_header_is_readable() {
        let enc = encrypt_store(&signal_shaped_plaintext(2), &KEY, &SALT, 32);
        let wrong = spec(&[0x5d; 32], &SALT);
        assert!(
            decrypt_v4_raw_key(&enc, &wrong, &SqlCipher4Config::signal_ios()).is_none(),
            "a wrong key must be refused, not returned as garbage behind a genuine header"
        );
    }

    #[test]
    fn a_tampered_page_under_hmac_sha512_is_named() {
        let plain = signal_shaped_plaintext(3);
        let mut enc = encrypt_store(&plain, &KEY, &SALT, 32);
        enc[4096 * 2 + 500] ^= 0x04;
        let d = decrypt_v4_raw_key(&enc, &spec(&KEY, &SALT), &SqlCipher4Config::signal_ios())
            .expect("page 1 is intact, so the key is established");
        assert!(!d.integrity_verified);
        assert_eq!(d.failed_pages, vec![3]);
        assert!(
            d.integrity_statement.contains("HMAC"),
            "{}",
            d.integrity_statement
        );
    }

    /// Two genuine pages exchanged: the page number is authenticated.
    #[test]
    fn resequenced_pages_are_caught_under_sqlcipher_4() {
        let plain = signal_shaped_plaintext(4);
        let enc = encrypt_store(&plain, &KEY, &SALT, 32);
        let mut swapped = enc.clone();
        swapped[2 * 4096..3 * 4096].copy_from_slice(&enc[3 * 4096..4 * 4096]);
        swapped[3 * 4096..4 * 4096].copy_from_slice(&enc[2 * 4096..3 * 4096]);
        let d = decrypt_v4_raw_key(
            &swapped,
            &spec(&KEY, &SALT),
            &SqlCipher4Config::signal_ios(),
        )
        .unwrap();
        assert_eq!(d.failed_pages, vec![3, 4]);
    }

    /// SQLCipher 4's default layout keeps the salt in the file's first 16
    /// bytes. A 32-byte raw key takes its salt from there; a 48-byte spec whose
    /// salt disagrees with the file's belongs to another database.
    #[test]
    fn with_no_plaintext_header_the_salt_is_read_from_the_file() {
        let plain = signal_shaped_plaintext(2);
        let enc = encrypt_store(&plain, &KEY, &SALT, 0);
        assert_eq!(&enc[0..16], &SALT);
        let cfg = SqlCipher4Config {
            page_size: 4096,
            plaintext_header_size: 0,
            use_hmac: true,
        };
        let d = decrypt_v4_raw_key(&enc, &RawKeySpec::from_bytes(&KEY).unwrap(), &cfg)
            .expect("a 32-byte raw key with the salt in the file");
        assert_eq!(&d.plaintext[16..], &plain[16..]);
        assert_eq!(&d.plaintext[0..16], b"SQLite format 3\0");
        assert!(d.integrity_verified);
        assert!(
            decrypt_v4_raw_key(&enc, &spec(&KEY, &[0x01; 16]), &cfg).is_none(),
            "a key spec whose salt is not this file's must be refused"
        );
    }

    /// A plaintext header hides the salt, so a key with no salt cannot derive
    /// the HMAC key. SQLCipher itself cannot open such a store without it; nor
    /// is anything here to be presented as authenticated without it.
    #[test]
    fn a_plaintext_header_store_needs_the_salt_in_the_key_spec() {
        let enc = encrypt_store(&signal_shaped_plaintext(2), &KEY, &SALT, 32);
        assert!(decrypt_v4_raw_key(
            &enc,
            &RawKeySpec::from_bytes(&KEY).unwrap(),
            &SqlCipher4Config::signal_ios()
        )
        .is_none());
    }

    // --- the write-ahead log --------------------------------------------------

    fn wal_checksum(big_endian: bool, data: &[u8], init: (u32, u32)) -> (u32, u32) {
        let (mut s0, mut s1) = init;
        for w in data.as_chunks::<8>().0 {
            let rd = |b: &[u8]| {
                let a: [u8; 4] = b.try_into().unwrap();
                if big_endian {
                    u32::from_be_bytes(a)
                } else {
                    u32::from_le_bytes(a)
                }
            };
            s0 = s0.wrapping_add(rd(&w[0..4])).wrapping_add(s1);
            s1 = s1.wrapping_add(rd(&w[4..8])).wrapping_add(s0);
        }
        (s0, s1)
    }

    /// A WAL SQLite would replay: frames `(page_number, commit_size, page)`.
    pub(super) fn build_wal(frames: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&0x377f_0682u32.to_be_bytes()); // little-endian checksums
        w.extend_from_slice(&3_007_000u32.to_be_bytes());
        w.extend_from_slice(&4096u32.to_be_bytes());
        w.extend_from_slice(&6u32.to_be_bytes());
        w.extend_from_slice(&0x8b05_2f6eu32.to_be_bytes());
        w.extend_from_slice(&0x3f3c_7b30u32.to_be_bytes());
        let mut ck = wal_checksum(false, &w[0..24], (0, 0));
        w.extend_from_slice(&ck.0.to_be_bytes());
        w.extend_from_slice(&ck.1.to_be_bytes());
        for (pgno, commit, page) in frames {
            let mut fh = Vec::new();
            fh.extend_from_slice(&pgno.to_be_bytes());
            fh.extend_from_slice(&commit.to_be_bytes());
            fh.extend_from_slice(&w[16..24]);
            ck = wal_checksum(false, &fh[0..8], ck);
            ck = wal_checksum(false, page, ck);
            fh.extend_from_slice(&ck.0.to_be_bytes());
            fh.extend_from_slice(&ck.1.to_be_bytes());
            w.extend_from_slice(&fh);
            w.extend_from_slice(page);
        }
        w
    }

    fn frame_is_valid_in_chain(w: &[u8], upto: usize) -> bool {
        let mut ck = wal_checksum(false, &w[0..24], (0, 0));
        if ck
            != (
                u32::from_be_bytes(w[24..28].try_into().unwrap()),
                u32::from_be_bytes(w[28..32].try_into().unwrap()),
            )
        {
            return false;
        }
        for i in 0..upto {
            let f = 32 + i * (24 + 4096);
            ck = wal_checksum(false, &w[f..f + 8], ck);
            ck = wal_checksum(false, &w[f + 24..f + 24 + 4096], ck);
            if w[f + 8..f + 16] != w[16..24]
                || ck
                    != (
                        u32::from_be_bytes(w[f + 16..f + 20].try_into().unwrap()),
                        u32::from_be_bytes(w[f + 20..f + 24].try_into().unwrap()),
                    )
            {
                return false;
            }
        }
        true
    }

    /// Signal's newest writes live in `signal.sqlite-wal`, encrypted page by
    /// page like the store. The committed frames come back as plaintext in a
    /// WAL whose checksum chain SQLite accepts; an uncommitted tail — which
    /// SQLite would not replay either — is counted and not presented.
    #[test]
    fn committed_wal_frames_decrypt_into_a_log_sqlite_would_replay() {
        let plain = signal_shaped_plaintext(3);
        let mut newer2 = plain[4096..8192].to_vec();
        newer2[100] ^= 0xff;
        let mut newer3 = plain[8192..12288].to_vec();
        newer3[200] ^= 0xff;
        let enc = |p: &[u8], n: u32| encrypt_page(p, n, &KEY, &SALT, 32, false, 0x20);
        let wal = build_wal(&[
            (2, 0, enc(&newer2, 2)),
            (1, 3, enc(&plain[0..4096], 1)),
            (3, 0, enc(&newer3, 3)), // no commit follows: SQLite ignores it
        ]);

        let d = decrypt_v4_raw_key_wal(&wal, &spec(&KEY, &SALT), &SqlCipher4Config::signal_ios())
            .expect("a well-formed WAL under the right key");
        assert_eq!(d.frames_in_file, 3);
        assert_eq!(d.frames_committed, 2);
        assert_eq!(d.frames_not_committed, 1);
        assert!(d.integrity_verified, "{}", d.integrity_statement);
        assert!(d.failed_frames.is_empty());
        assert!(d.wal_statement.contains('1'), "{}", d.wal_statement);

        let out = &d.plaintext_wal;
        assert_eq!(out.len(), 32 + 2 * (24 + 4096), "only the committed frames");
        assert_eq!(&out[32 + 24..32 + 24 + 4096], &newer2[..]);
        assert_eq!(&out[32 + 2 * 24 + 4096..], &plain[0..4096]);
        assert!(
            frame_is_valid_in_chain(out, 2),
            "the plaintext log's checksum chain must be one SQLite accepts"
        );
    }

    #[test]
    fn a_tampered_wal_frame_is_named() {
        let plain = signal_shaped_plaintext(2);
        let enc = |p: &[u8], n: u32| encrypt_page(p, n, &KEY, &SALT, 32, false, 0x30);
        let mut f2 = enc(&plain[4096..8192], 2);
        f2[900] ^= 0x01;
        let wal = build_wal(&[(1, 0, enc(&plain[0..4096], 1)), (2, 2, f2)]);
        let d = decrypt_v4_raw_key_wal(&wal, &spec(&KEY, &SALT), &SqlCipher4Config::signal_ios())
            .unwrap();
        assert!(!d.integrity_verified);
        assert_eq!(d.failed_frames, vec![2], "frames are named 1-based");
        assert!(
            d.integrity_statement.contains("frame"),
            "{}",
            d.integrity_statement
        );
    }
}
