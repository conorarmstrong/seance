//! AES-256-GCM decryption with the tag checked before any plaintext is
//! released (NIST SP 800-38D).
//!
//! Written here on the `aes` block cipher the workspace already carries, rather
//! than pulling in an AEAD crate for one caller. It handles an IV of any
//! length — WhatsApp's `crypt14` uses 16 bytes, not GCM's usual 12 — by
//! deriving the pre-counter block with GHASH as the standard prescribes. It is
//! pinned by the GCM specification's AES-256 test case and by vectors made with
//! OpenSSL (through Python's `cryptography`) for a 16-byte IV.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;

/// Why a decryption produced nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum GcmError {
    /// The authentication tag did not verify: the key is wrong, or the IV,
    /// ciphertext or tag is not what was encrypted. No plaintext is returned.
    TagMismatch,
    /// An empty IV, which GCM does not define.
    EmptyIv,
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

/// Decrypt `ciphertext` under `key` and `iv` with no additional data, and
/// return the plaintext only if `tag` verifies.
pub fn decrypt(
    key: &[u8; 32],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, GcmError> {
    if iv.is_empty() {
        return Err(GcmError::EmptyIv);
    }
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let h = encrypt_block(&cipher, 0);
    let j0 = if iv.len() == 12 {
        let mut b = [0u8; 16];
        b[..12].copy_from_slice(iv);
        b[15] = 1;
        u128::from_be_bytes(b)
    } else {
        let y = ghash_blocks(h, 0, iv);
        gf_mul(y ^ ((iv.len() as u128) * 8), h)
    };

    // The tag covers the ciphertext: S = GHASH(C || len(A) || len(C)).
    let s = ghash_blocks(h, 0, ciphertext);
    let s = gf_mul(s ^ ((ciphertext.len() as u128) * 8), h);
    let expected = (encrypt_block(&cipher, j0) ^ s).to_be_bytes();
    // Constant-time compare: the decision does not leak where they differ.
    let diff = expected
        .iter()
        .zip(tag.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(GcmError::TagMismatch);
    }

    let mut out = Vec::with_capacity(ciphertext.len());
    let mut counter = inc32(j0);
    for chunk in ciphertext.chunks(16) {
        let ks = encrypt_block(&cipher, counter).to_be_bytes();
        out.extend(chunk.iter().zip(ks.iter()).map(|(c, k)| c ^ k));
        counter = inc32(counter);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn tag(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }

    /// The GCM specification's Test Case 14 (AES-256, zero key, 96-bit zero
    /// IV, one zero block).
    #[test]
    fn gcm_spec_test_case_14() {
        let pt = decrypt(
            &[0u8; 32],
            &[0u8; 12],
            &hex("cea7403d4d606b6e074ec5d3baf39d18"),
            &tag("d0d1c8a799996bf0265b98b5d48ab919"),
        )
        .unwrap();
        assert_eq!(pt, vec![0u8; 16]);
    }

    /// A 16-byte IV, as `crypt14` uses, and a length that is not whole blocks:
    /// the vector was made with OpenSSL through Python's `cryptography`
    /// (`AESGCM(bytes(range(32))).encrypt(bytes(range(100, 116)), p, None)`).
    #[test]
    fn a_16_byte_iv_matches_openssl() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let iv: Vec<u8> = (100u8..116).collect();
        let plain: Vec<u8> = (0..100u32).map(|i| (i * 7) as u8).collect();
        let ct = hex(
            "d8b44d44f8370de98ac6ebc4138c8e0c2a062645107c7aaa6d2fa2d35d3cd5119b2660399cc8e9d0\
             19106928234a8e7b890a1a92cd923e62a89b488214e43195b5de695ba50736b374977fc3257a8b5\
             54c2212b73f144d871931d0db29eef0f233d43596",
        );
        let t = tag("dbb9bca4761f506df21290fcb5bb2565");
        assert_eq!(decrypt(&key, &iv, &ct, &t).unwrap(), plain);

        // One flipped bit anywhere, or the wrong key, and nothing comes back.
        let mut bad = ct.clone();
        bad[50] ^= 1;
        assert_eq!(decrypt(&key, &iv, &bad, &t), Err(GcmError::TagMismatch));
        let mut wrong = key;
        wrong[0] ^= 0x80;
        assert_eq!(decrypt(&wrong, &iv, &ct, &t), Err(GcmError::TagMismatch));
        let mut bad_tag = t;
        bad_tag[15] ^= 1;
        assert_eq!(
            decrypt(&key, &iv, &ct, &bad_tag),
            Err(GcmError::TagMismatch)
        );
    }
}
