//! Classic `kych` keychain secret decryption.
//!
//! Given the login password (or, for `System.keychain`, the bytes of
//! `/var/db/SystemKey`), this recovers a keychain's secrets by the same unwrap
//! the CDSA `securityd` performs, in three steps:
//!
//! 1. **PBKDF2-HMAC-SHA1** over the password with the `DbBlob`'s 20-byte salt,
//!    [`PBKDF2_ITERATIONS`] iterations, 24 bytes out — the key that unwraps the
//!    database.
//! 2. **3DES-EDE-CBC** decryption of the `DbBlob`'s encrypted region with that
//!    key and the blob's 8-byte IV. A wrong password is caught here and only
//!    here: the decrypted block is not validly PKCS#7-padded, so
//!    [`unwrap_db_master_key`] returns [`UnlockError::WrongPassword`] rather
//!    than a plausible-looking wrong key. The recovered bytes are the database
//!    master key.
//! 3. per item, the wrapped item key is unwrapped from the master key with the
//!    RFC 3217 3DES key-unwrap ([`unwrap_item_key`]: the CSSM magic IV
//!    `4adda22c79e82105` and a reversed intermediate), and the item's `ssgp`
//!    record body is 3DES-CBC decrypted under that item key ([`decrypt_ssgp`]).
//!
//! # What is validated, and what is only pinned
//!
//! **Steps 1 and 2 are graded on real evidence, and step 3 on one keychain.** The two openwall
//! John-the-Ripper sample keychains (passwords `password` and `letmein`) unwrap
//! to master keys that match an independent Python implementation byte for byte,
//! and any other password is `WrongPassword`
//! (`tests/john_keychain_unlock.rs`, `VALIDATION.md` `KEYCHAIN-1`). Both files
//! hold zero `ssgp` items, so step 3 could not be graded on them. It is graded on
//! moond4rk/keychainbreaker's `test.keychain-db`, made by macOS's `security`
//! command with a published password and answer: [`unwrap_item_key`] and
//! [`decrypt_ssgp`], called through `decrypt_item_secrets`, recover all four
//! password items' published secret (`tests/keychain_items_real.rs`,
//! `VALIDATION.md` `KEYCHAIN-2`). The item key is the 24 bytes after the
//! unwrapped block's 12-byte header, which the unit tests' round trips could not
//! have shown.
//!
//! **The `SystemKey` route skips step 1.** `System.keychain` has no password; its
//! `DbBlob` is wrapped directly under the 24-byte key at bytes 8 to 32 of the
//! 48-byte `/var/db/SystemKey` ([`system_key_to_db_key`]). That layout and the
//! route are graded on the macOS 11.2.1 System.keychain and SystemKey of the
//! Hickman Big Sur image, against an independent Python unwrap and chainbreaker
//! (`tests/keychain_system_key.rs`, `VALIDATION.md` `KEYCHAIN-3`).
//!
//! Nothing in this module derives, guesses or brute-forces a password: it is
//! handed one, or it does nothing.

use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;
use sha1::Sha1;

/// 3DES-EDE-CBC decryptor over the classic keychain's wrapping cipher.
type Tdes3CbcDec = cbc::Decryptor<TdesEde3>;

/// PBKDF2 iteration count the `kych` format fixes. The file does not carry it.
pub const PBKDF2_ITERATIONS: u32 = 1000;
/// Length of the PBKDF2-derived key: a 24-byte 3DES-EDE key.
pub const DERIVED_KEY_LEN: usize = 24;
/// The 3DES block, in bytes.
const DES_BLOCK: usize = 8;

/// The fixed CBC IV RFC 3217 (and CDSA) use for the outer pass of the 3DES key
/// unwrap. `kSecMagicBytes` in Apple's `securityd`.
pub const CSSM_WRAP_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// Why an unwrap did not yield a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockError {
    /// The derived key did not decrypt to a validly PKCS#7-padded block: the
    /// password (or `SystemKey`) is wrong. This is the only outcome for a
    /// wrong password, and it is never returned for a right one.
    WrongPassword,
    /// The ciphertext is empty or not a whole number of 3DES blocks — a
    /// malformed or truncated blob, told apart from a wrong password.
    NotBlockAligned,
    /// The bytes handed in as `/var/db/SystemKey` are not a SystemKey file
    /// (wrong length or magic), told apart from a SystemKey that is right in
    /// shape and wrong for this keychain.
    NotASystemKey,
}

impl UnlockError {
    /// Stable label for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            UnlockError::WrongPassword => "wrong_password",
            UnlockError::NotBlockAligned => "ciphertext_not_block_aligned",
            UnlockError::NotASystemKey => "not_a_system_key",
        }
    }
}

/// PBKDF2-HMAC-SHA1 (RFC 2898), filling `out` from `password` and `salt`.
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, iterations, out);
}

/// 3DES-EDE-CBC decryption, returning the raw plaintext with padding **left
/// on**. `ciphertext` must be a positive multiple of the 3DES block.
pub fn des3_cbc_decrypt(
    key: &[u8; DERIVED_KEY_LEN],
    iv: &[u8; DES_BLOCK],
    ciphertext: &[u8],
) -> Result<Vec<u8>, UnlockError> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(DES_BLOCK) {
        return Err(UnlockError::NotBlockAligned);
    }
    let mut buf = ciphertext.to_vec();
    // NoPadding: decrypt every block and leave the plaintext whole, so the
    // caller decides whether the trailing bytes are valid PKCS#7 padding. That
    // decision is what tells a right password from a wrong one.
    Tdes3CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| UnlockError::NotBlockAligned)?;
    Ok(buf)
}

/// Strip PKCS#7 padding, returning [`UnlockError::WrongPassword`] when the
/// trailing bytes are not valid padding — which, on a keychain blob, means the
/// key that produced this plaintext was wrong.
pub fn pkcs7_unpad(plaintext: &[u8]) -> Result<&[u8], UnlockError> {
    let &last = plaintext.last().ok_or(UnlockError::WrongPassword)?;
    let pad = last as usize;
    if pad == 0 || pad > DES_BLOCK || pad > plaintext.len() {
        return Err(UnlockError::WrongPassword);
    }
    let cut = plaintext.len() - pad;
    if plaintext[cut..].iter().any(|&b| b as usize != pad) {
        return Err(UnlockError::WrongPassword);
    }
    Ok(&plaintext[..cut])
}

/// Derive the 24-byte database-unwrapping key from a password and the
/// `DbBlob`'s salt.
pub fn derive_db_key(password: &[u8], salt: &[u8]) -> [u8; DERIVED_KEY_LEN] {
    let mut key = [0u8; DERIVED_KEY_LEN];
    pbkdf2_hmac_sha1(password, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Unwrap the database master key from the `DbBlob`'s encrypted region under
/// a key already in hand (no PBKDF2): the `SystemKey` route.
pub fn unwrap_db_master_key_with_key(
    key: &[u8; DERIVED_KEY_LEN],
    iv: &[u8; DES_BLOCK],
    ciphertext: &[u8],
) -> Result<Vec<u8>, UnlockError> {
    let plain = des3_cbc_decrypt(key, iv, ciphertext)?;
    Ok(pkcs7_unpad(&plain)?.to_vec())
}

/// The length of `/var/db/SystemKey`: an 8-byte header, the 24-byte 3DES key
/// and a 16-byte signature.
pub const SYSTEM_KEY_LEN: usize = 48;
/// The first four bytes of a `SystemKey` (the CDSA blob magic, `0xFADE0711`).
const SYSTEM_KEY_MAGIC: [u8; 4] = [0xfa, 0xde, 0x07, 0x11];

/// The 3DES key inside a `/var/db/SystemKey` file: bytes 8 to 32 of its 48.
///
/// Only the shape is checked here (length, magic). Whether the key opens a
/// given keychain is decided, as for a password, by the padding of the
/// unwrapped block. The layout was found on a real file by trying every
/// 24-byte window against a `DbBlob` (exactly one opens it) and agrees with
/// chainbreaker's `8s 24s 16s`; the signature is not verified.
pub fn system_key_to_db_key(file: &[u8]) -> Result<[u8; DERIVED_KEY_LEN], UnlockError> {
    if file.len() != SYSTEM_KEY_LEN || file[..4] != SYSTEM_KEY_MAGIC {
        return Err(UnlockError::NotASystemKey);
    }
    file[8..8 + DERIVED_KEY_LEN]
        .try_into()
        .map_err(|_| UnlockError::NotASystemKey)
}

/// Unwrap the database master key from the `DbBlob`'s encrypted region.
///
/// Returns the recovered master-key bytes on success, or
/// [`UnlockError::WrongPassword`] when the password does not open the blob.
pub fn unwrap_db_master_key(
    password: &[u8],
    salt: &[u8],
    iv: &[u8; DES_BLOCK],
    ciphertext: &[u8],
) -> Result<Vec<u8>, UnlockError> {
    let key = derive_db_key(password, salt);
    let plain = des3_cbc_decrypt(&key, iv, ciphertext)?;
    Ok(pkcs7_unpad(&plain)?.to_vec())
}

/// The `DbBlob`'s crypto material: what [`unwrap_db_master_key`] consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbBlobCrypto {
    /// 20-byte PBKDF2 salt.
    pub salt: [u8; 20],
    /// 8-byte CBC initialisation vector.
    pub iv: [u8; DES_BLOCK],
    /// The encrypted master-key region (a multiple of the 3DES block).
    pub ciphertext: Vec<u8>,
}

impl DbBlobCrypto {
    /// Unwrap the master key from this blob with `password`.
    pub fn unwrap(&self, password: &[u8]) -> Result<Vec<u8>, UnlockError> {
        unwrap_db_master_key(password, &self.salt, &self.iv, &self.ciphertext)
    }

    /// Unwrap the master key from this blob with the 3DES key a
    /// `/var/db/SystemKey` file carries.
    pub fn unwrap_with_system_key(&self, system_key: &[u8]) -> Result<Vec<u8>, UnlockError> {
        let key = system_key_to_db_key(system_key)?;
        unwrap_db_master_key_with_key(&key, &self.iv, &self.ciphertext)
    }
}

/// RFC 3217 3DES key unwrap, as CDSA uses it to wrap each item key under the
/// database master key.
///
/// `wrapped` is a whole number of 3DES blocks. The unwrap CBC-decrypts it under
/// the fixed [`CSSM_WRAP_IV`], reverses the octet order, takes the first block
/// as the IV for a second CBC pass, and PKCS#7-unpads the result.
///
/// This mechanism is pinned by a synthetic round-trip test only; it is not
/// validated on real evidence in this crate.
pub fn unwrap_item_key(
    master_key: &[u8; DERIVED_KEY_LEN],
    wrapped: &[u8],
) -> Result<Vec<u8>, UnlockError> {
    let mut temp = des3_cbc_decrypt(master_key, &CSSM_WRAP_IV, wrapped)?;
    temp.reverse();
    if temp.len() <= DES_BLOCK {
        return Err(UnlockError::NotBlockAligned);
    }
    let (iv, body) = temp.split_at(DES_BLOCK);
    let iv: [u8; DES_BLOCK] = iv.try_into().expect("split at DES_BLOCK");
    let plain = des3_cbc_decrypt(master_key, &iv, body)?;
    Ok(pkcs7_unpad(&plain)?.to_vec())
}

/// Decrypt an `ssgp` record body under an item key and the record's own IV.
///
/// Graded on four real `ssgp` items with a published answer (`KEYCHAIN-2`).
pub fn decrypt_ssgp(
    item_key: &[u8; DERIVED_KEY_LEN],
    iv: &[u8; DES_BLOCK],
    body: &[u8],
) -> Result<Vec<u8>, UnlockError> {
    let plain = des3_cbc_decrypt(item_key, iv, body)?;
    Ok(pkcs7_unpad(&plain)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::block_padding::NoPadding as NoPad;
    use cbc::cipher::BlockEncryptMut;

    type Tdes3CbcEnc = cbc::Encryptor<TdesEde3>;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// 3DES-EDE-CBC encrypt, no padding added, for building test fixtures.
    fn des3_cbc_encrypt(key: &[u8; 24], iv: &[u8; 8], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let n = buf.len();
        Tdes3CbcEnc::new(key.into(), iv.into())
            .encrypt_padded_mut::<NoPad>(&mut buf, n)
            .unwrap()
            .to_vec()
    }

    /// PKCS#7-pad to the 3DES block.
    fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
        let pad = DES_BLOCK - (data.len() % DES_BLOCK);
        let mut out = data.to_vec();
        out.extend(std::iter::repeat_n(pad as u8, pad));
        out
    }

    // --- RED-first primitives, against published/known answers ---------------

    #[test]
    fn pbkdf2_hmac_sha1_matches_rfc6070() {
        // RFC 6070 §2: P="password", S="salt", dkLen=20.
        let mut out = [0u8; 20];
        pbkdf2_hmac_sha1(b"password", b"salt", 1, &mut out);
        assert_eq!(hex(&out), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
        pbkdf2_hmac_sha1(b"password", b"salt", 4096, &mut out);
        assert_eq!(hex(&out), "4b007901b765489abead49d926f721d065a429c1");
    }

    #[test]
    fn pbkdf2_first_20_bytes_of_a_24_byte_derivation_equal_the_20_byte_answer() {
        // PBKDF2 concatenates independent blocks and truncates, so a longer
        // derivation extends a shorter one — the property the DbBlob key relies
        // on, since RFC 6070 publishes 20-byte answers and the key is 24.
        let mut twenty = [0u8; 20];
        pbkdf2_hmac_sha1(b"password", b"salt", PBKDF2_ITERATIONS, &mut twenty);
        let twenty_four = derive_db_key(b"password", b"salt");
        assert_eq!(&twenty_four[..20], &twenty[..]);
        // Independent answer for 1000 iterations (Python hashlib.pbkdf2_hmac).
        assert_eq!(hex(&twenty), "6e88be8bad7eae9d9e10aa061224034fed48d03f");
    }

    #[test]
    fn des3_cbc_known_answer() {
        // Cross-implementation known answer generated with OpenSSL (via Python
        // `cryptography`): TripleDES-CBC encrypt of a 16-byte block.
        let key: [u8; 24] = unhex("0123456789abcdef23456789abcdef01456789abcdef0123")
            .try_into()
            .unwrap();
        let iv: [u8; 8] = unhex("1234567890abcdef").try_into().unwrap();
        let plaintext = b"Now is the time!";
        let ciphertext = unhex("f3c0ff026c023089273a393be912a18c");
        // Decrypt reproduces the plaintext.
        let got = des3_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&got, plaintext);
        // And our own encrypt reproduces the reference ciphertext.
        assert_eq!(des3_cbc_encrypt(&key, &iv, plaintext), ciphertext);
    }

    #[test]
    fn pkcs7_unpad_accepts_valid_and_rejects_invalid() {
        assert_eq!(
            pkcs7_unpad(&[0xaa, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06]).unwrap(),
            &[0xaa]
        );
        assert_eq!(
            pkcs7_unpad(&[1, 2, 3, 4, 5, 6, 7, 8]),
            Err(UnlockError::WrongPassword)
        ); // pad 8 but bytes differ
        assert_eq!(pkcs7_unpad(&[0x09; 9]), Err(UnlockError::WrongPassword)); // pad > block
        assert_eq!(pkcs7_unpad(&[0x00]), Err(UnlockError::WrongPassword)); // pad 0
        assert_eq!(pkcs7_unpad(&[]), Err(UnlockError::WrongPassword));
    }

    // --- DbBlob unwrap, on a synthetic blob (real evidence lives in the
    //     corpus-gated integration test) ------------------------------------

    #[test]
    fn db_master_key_round_trips_and_a_wrong_password_is_refused() {
        let salt = [0x11u8; 20];
        let iv = [0x22u8; 8];
        let master = b"a 40-byte database master key blob......"; // 40 bytes
        assert_eq!(master.len(), 40);
        let key = derive_db_key(b"correct horse", &salt);
        let ct = des3_cbc_encrypt(&key, &iv, &pkcs7_pad(master));
        let blob = DbBlobCrypto {
            salt,
            iv,
            ciphertext: ct,
        };

        assert_eq!(blob.unwrap(b"correct horse").unwrap(), master);
        assert_eq!(
            blob.unwrap(b"wrong password"),
            Err(UnlockError::WrongPassword)
        );
    }

    fn system_key_file(db_key: &[u8; 24]) -> Vec<u8> {
        let mut f = vec![0xfa, 0xde, 0x07, 0x11, 0, 0, 0, 0];
        f.extend_from_slice(db_key);
        f.extend_from_slice(&[0x5a; 16]);
        f
    }

    #[test]
    fn a_system_key_unwraps_the_db_blob_without_pbkdf2_and_a_wrong_one_is_refused() {
        let db_key = [0x42u8; 24];
        let iv = [0x22u8; 8];
        let master = b"a 40-byte database master key blob......";
        let blob = DbBlobCrypto {
            salt: [0x11; 20],
            iv,
            ciphertext: des3_cbc_encrypt(&db_key, &iv, &pkcs7_pad(master)),
        };
        assert_eq!(
            blob.unwrap_with_system_key(&system_key_file(&db_key))
                .unwrap(),
            master
        );
        assert_eq!(
            blob.unwrap_with_system_key(&system_key_file(&[0xc2; 24])),
            Err(UnlockError::WrongPassword)
        );
    }

    #[test]
    fn a_file_that_is_not_a_system_key_is_told_apart_from_a_wrong_one() {
        let good = system_key_file(&[1; 24]);
        assert!(system_key_to_db_key(&good).is_ok());
        assert_eq!(
            system_key_to_db_key(&good[..47]),
            Err(UnlockError::NotASystemKey)
        );
        let mut bad_magic = good.clone();
        bad_magic[3] = 0x12;
        assert_eq!(
            system_key_to_db_key(&bad_magic),
            Err(UnlockError::NotASystemKey)
        );
    }

    #[test]
    fn a_ciphertext_that_is_not_block_aligned_is_told_apart_from_a_wrong_password() {
        let salt = [0u8; 20];
        let iv = [0u8; 8];
        let blob = DbBlobCrypto {
            salt,
            iv,
            ciphertext: vec![0u8; 7],
        };
        assert_eq!(blob.unwrap(b"anything"), Err(UnlockError::NotBlockAligned));
    }

    // --- item-key unwrap + ssgp decrypt: MECHANISM ONLY (round-trip). No real
    //     ssgp evidence in the corpus, so this pins the algorithm, not a
    //     recovery on evidence. -----------------------------------------------

    #[test]
    fn item_key_unwrap_inverts_the_rfc3217_wrap_mechanism_only() {
        let master = derive_db_key(b"db", &[0x55u8; 20]);
        let item_key = b"an item key, 24 bytes...";
        assert_eq!(item_key.len(), 24);

        // Wrap: the inverse of unwrap_item_key. inner CBC-encrypt under a random
        // IV, prepend the IV, reverse, outer CBC-encrypt under the magic IV.
        let inner_iv = [0x77u8; 8];
        let inner = des3_cbc_encrypt(&master, &inner_iv, &pkcs7_pad(item_key));
        let mut pre = inner_iv.to_vec();
        pre.extend_from_slice(&inner);
        pre.reverse();
        let wrapped = des3_cbc_encrypt(&master, &CSSM_WRAP_IV, &pre);

        assert_eq!(unwrap_item_key(&master, &wrapped).unwrap(), item_key);
    }

    #[test]
    fn ssgp_decrypt_inverts_a_3des_cbc_record_mechanism_only() {
        let item_key = derive_db_key(b"item", &[0x33u8; 20]);
        let iv = [0x44u8; 8];
        let secret = b"hunter2";
        let body = des3_cbc_encrypt(&item_key, &iv, &pkcs7_pad(secret));
        assert_eq!(decrypt_ssgp(&item_key, &iv, &body).unwrap(), secret);
        // A wrong key is refused rather than returning garbage.
        let wrong = derive_db_key(b"nope", &[0x33u8; 20]);
        assert_eq!(
            decrypt_ssgp(&wrong, &iv, &body),
            Err(UnlockError::WrongPassword)
        );
    }
}
