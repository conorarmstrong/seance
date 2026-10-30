//! AES-256-GCM as the iOS keychain uses it (HUNT-111).
//!
//! A keychain item in `keychain-backup.plist` stores its attributes as
//! AES-256-GCM ciphertext with a **zero-length IV** and the 16-byte tag
//! appended. GCM defines an IV of any length other than 96 bits through GHASH
//! (SP 800-38D 7.1): for an empty IV the pre-counter block `J0` is
//! `GHASH_H(0^128)`, which is zero, so the keystream starts at `inc32(0)`.
//! Common AEAD APIs refuse an empty nonce, which is why this is written here
//! on the `aes` block cipher the crate already carries rather than taken from
//! an AEAD crate.
//!
//! The tag is always checked before any plaintext is released: a failed tag
//! returns [`GcmError::TagMismatch`] and no bytes. The plaintext comes back in
//! a zeroizing buffer because for a keychain item it contains the secret.
//!
//! Pinned by the GCM specification's Test Case 18 inputs (60-byte IV, with
//! AAD) against OpenSSL's output, and — the real check — by the Hickman iOS 17
//! backup, where every one of the 653 items whose key unwraps also verifies its
//! tag (`tests/hickman_ios17_keychain.rs`).

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use zeroize::Zeroizing;

/// Why a decryption produced nothing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GcmError {
    /// The authentication tag did not verify: the key is wrong or the
    /// ciphertext or tag is not what was encrypted. No plaintext is returned.
    TagMismatch,
    /// The input is shorter than a tag.
    Truncated,
}

impl std::fmt::Display for GcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcmError::TagMismatch => f.write_str("the AES-GCM authentication tag did not verify"),
            GcmError::Truncated => f.write_str("the AES-GCM payload is shorter than its tag"),
        }
    }
}

/// Multiply two elements of GF(2^128) in GCM's bit order (SP 800-38D 6.3).
fn gf_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xE1 << 120;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    z
}

/// GHASH over `data` zero-padded to whole blocks, continuing from `y`.
fn ghash_blocks(h: u128, mut y: u128, data: &[u8]) -> u128 {
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        y = gf_mul(y ^ u128::from_be_bytes(block), h);
    }
    y
}

fn encrypt_block(cipher: &Aes256, block: u128) -> u128 {
    let mut b = GenericArray::from(block.to_be_bytes());
    cipher.encrypt_block(&mut b);
    u128::from_be_bytes(b.into())
}

/// Increment the low 32 bits of a counter block (SP 800-38D `inc32`).
fn inc32(block: u128) -> u128 {
    let low = (block as u32).wrapping_add(1);
    (block & !0xFFFF_FFFFu128) | low as u128
}

fn pre_counter(h: u128, iv: &[u8]) -> u128 {
    if iv.len() == 12 {
        let mut b = [0u8; 16];
        b[..12].copy_from_slice(iv);
        b[15] = 1;
        u128::from_be_bytes(b)
    } else {
        // Any other length, including zero: J0 = GHASH(IV || pad || [len(IV)]_64).
        let y = ghash_blocks(h, 0, iv);
        gf_mul(y ^ ((iv.len() as u128) * 8), h)
    }
}

fn tag_for(cipher: &Aes256, h: u128, j0: u128, aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let s = ghash_blocks(h, 0, aad);
    let s = ghash_blocks(h, s, ct);
    let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
    let s = gf_mul(s ^ lens, h);
    (encrypt_block(cipher, j0) ^ s).to_be_bytes()
}

fn ctr(cipher: &Aes256, j0: u128, data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    let mut counter = inc32(j0);
    for chunk in data.chunks(16) {
        let ks = encrypt_block(cipher, counter).to_be_bytes();
        out.extend(chunk.iter().zip(ks.iter()).map(|(c, k)| c ^ k));
        counter = inc32(counter);
    }
    out
}

/// Decrypt `ciphertext` under `key`, `iv` and `aad`, returning the plaintext
/// only if `tag` verifies.
pub(crate) fn open(
    key: &[u8; 32],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Zeroizing<Vec<u8>>, GcmError> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let h = encrypt_block(&cipher, 0);
    let j0 = pre_counter(h, iv);
    let expected = tag_for(&cipher, h, j0, aad, ciphertext);
    // Constant-time compare: the decision does not leak where they differ.
    let diff = expected
        .iter()
        .zip(tag.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(GcmError::TagMismatch);
    }
    Ok(ctr(&cipher, j0, ciphertext))
}

/// The keychain's form: an empty IV, no AAD, the tag on the end.
pub(crate) fn decrypt_empty_iv(
    key: &[u8; 32],
    ct_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, GcmError> {
    if ct_with_tag.len() < 16 {
        return Err(GcmError::Truncated);
    }
    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);
    let tag: [u8; 16] = tag.try_into().expect("split at 16");
    open(key, &[], &[], ct, &tag)
}

/// Encrypt the way the keychain does (empty IV, tag appended). Used only to
/// build synthetic fixtures; nothing in the product encrypts.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn encrypt_empty_iv(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let h = encrypt_block(&cipher, 0);
    let j0 = pre_counter(h, &[]);
    let mut out = ctr(&cipher, j0, plaintext).to_vec();
    let tag = tag_for(&cipher, h, j0, &[], &out);
    out.extend_from_slice(&tag);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// The GCM specification's Test Case 18 inputs (AES-256, a 60-byte IV —
    /// the not-96-bit branch the empty IV also takes — and 20 bytes of AAD).
    /// The expected ciphertext and tag were produced by OpenSSL through
    /// Python `cryptography` 46.0.5 from the same inputs.
    #[test]
    fn gcm_ghash_matches_spec_test_case_18_inputs() {
        let key: [u8; 32] = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .try_into()
            .unwrap();
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let iv = hex(
            "9313225df88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let ct = hex(
            "ad91c20c78578a3e00a17347f616a4ef7dcd5ec3943ee3be1b08cc36222b1d81\
             d7321dcbcb742fe5668d3df781ce8580d83d7f11ca724410fe7ec496",
        );
        let tag: [u8; 16] = hex("1b234dbd410402a54dadffc11e7d70f3").try_into().unwrap();
        assert_eq!(open(&key, &iv, &aad, &ct, &tag).unwrap().to_vec(), pt);
    }

    /// An empty-IV vector made by the independent Python reader
    /// (AES-ECB from `cryptography` plus its own GHASH) whose derivation
    /// verified all 653 openable Hickman keychain items' tags.
    #[test]
    fn gcm_empty_iv_matches_the_python_reader() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let pt: Vec<u8> = (0..40u32).map(|i| (i * 7) as u8).collect();
        let sealed = hex(
            "f05a78bb569ab5d49ec9dd7c1c9954547ecbcb5b39bf191ca0071f88dce74340\
             32a4b8a6d4826a3e3de0b143d5204eb0f63c26a75a543a57",
        );
        assert_eq!(decrypt_empty_iv(&key, &sealed).unwrap().to_vec(), pt);
        assert_eq!(encrypt_empty_iv(&key, &pt), sealed);
    }

    #[test]
    fn gcm_empty_iv_roundtrip_and_tag_rejects_bitflip() {
        let key = [0x42u8; 32];
        let pt = b"acct=someone@example.com; the secret lives here".to_vec();
        let sealed = encrypt_empty_iv(&key, &pt);
        assert_eq!(decrypt_empty_iv(&key, &sealed).unwrap().to_vec(), pt);

        let mut bad_ct = sealed.clone();
        bad_ct[3] ^= 0x01;
        assert_eq!(decrypt_empty_iv(&key, &bad_ct), Err(GcmError::TagMismatch));
        let mut bad_tag = sealed.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 0x80;
        assert_eq!(decrypt_empty_iv(&key, &bad_tag), Err(GcmError::TagMismatch));
        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        assert_eq!(
            decrypt_empty_iv(&wrong_key, &sealed),
            Err(GcmError::TagMismatch)
        );
        assert_eq!(decrypt_empty_iv(&key, &[0u8; 15]), Err(GcmError::Truncated));
    }
}
