//! AES-CBC + Elephant diffuser sector decryption (BitLocker on Windows Vista/7/8,
//! FVE methods 0x8000/0x8001).
//!
//! The algorithm is Niels Ferguson's published "AES-CBC + Elephant diffuser"
//! (Microsoft, 2006); the exact constants and operation order were taken from
//! the public specification and the libbde reference, then **validated
//! byte-for-byte against the real `test_data/bdetogo.raw` volume** — empty
//! clusters decrypt to all-zeros and the relocated FAT boot sector decrypts to a
//! valid 0x55AA / `mkdosfs` boot record.
//!
//! Per sector, with `block_key` = the sector's byte offset in the volume:
//!
//! ```text
//! IV        = AES-ECB(FVEK-key, LE64(block_key)|0)
//! sectorkey = AES-ECB(TWEAK-key, block) | AES-ECB(TWEAK-key, block[15]=0x80)
//! plaintext = AES-CBC-decrypt(FVEK-key, IV) -> Diffuser-B^-1 -> Diffuser-A^-1
//!             -> XOR sectorkey (cyclic over 512 bytes)
//! ```

use crate::error::BitlockerError;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

const WORDS: usize = 128; // 512-byte sector / 4
const R_A: [u32; 4] = [9, 0, 13, 0];
const R_B: [u32; 4] = [0, 10, 0, 25];

#[inline]
fn rol(v: u32, n: u32) -> u32 {
    if n == 0 {
        v
    } else {
        v.rotate_left(n)
    }
}

/// Diffuser A decrypt (5 cycles). Runs "backwards" (index2/3 trail index1).
fn diffuser_a_decrypt(w: &mut [u32; WORDS]) {
    for _ in 0..5 {
        let (mut i2, mut i3) = (WORDS - 2, WORDS - 5);
        for i1 in 0..WORDS {
            w[i1] = w[i1].wrapping_add(w[i2] ^ rol(w[i3], R_A[i1 % 4]));
            i2 = (i2 + 1) % WORDS;
            i3 = (i3 + 1) % WORDS;
        }
    }
}

/// Diffuser B decrypt (3 cycles). Runs "forwards" (index2/3 lead index1).
fn diffuser_b_decrypt(w: &mut [u32; WORDS]) {
    for _ in 0..3 {
        let (mut i2, mut i3) = (2usize, 5usize);
        for i1 in 0..WORDS {
            w[i1] = w[i1].wrapping_add(w[i2] ^ rol(w[i3], R_B[i1 % 4]));
            i2 = (i2 + 1) % WORDS;
            i3 = (i3 + 1) % WORDS;
        }
    }
}

/// One AES-ECB block encryption with a 128- or 256-bit key.
fn ecb_encrypt(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let mut b = (*block).into();
    if key.len() == 32 {
        Aes256::new(key.into()).encrypt_block(&mut b);
    } else {
        Aes128::new(key.into()).encrypt_block(&mut b);
    }
    b.into()
}

/// AES-CBC decrypt in place (no padding) with a 128- or 256-bit key.
fn cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
    let mut prev = *iv;
    let decrypt_one = |b: &mut aes::cipher::generic_array::GenericArray<u8, _>| {
        if key.len() == 32 {
            Aes256::new(key.into()).decrypt_block(b);
        } else {
            Aes128::new(key.into()).decrypt_block(b);
        }
    };
    for chunk in data.as_chunks_mut::<16>().0 {
        // `as_chunks_mut` hands back a `&mut [u8; 16]` already, so this is a
        // copy of the ciphertext block rather than a fallible conversion.
        let ct: [u8; 16] = *chunk;
        let mut b = ct.into();
        decrypt_one(&mut b);
        let p: [u8; 16] = b.into();
        for i in 0..16 {
            chunk[i] = p[i] ^ prev[i];
        }
        prev = ct;
    }
}

/// Split a diffuser-mode FVEK into (AES key, TWEAK key). 0x8000 uses 128-bit
/// keys (16+16 of the 64-byte FVEK); 0x8001 uses 256-bit (32+32).
pub fn split_fvek(fvek: &[u8], aes256: bool) -> Result<(&[u8], &[u8]), BitlockerError> {
    if fvek.len() < 64 {
        return Err(BitlockerError::Malformed(
            "FVEK too short for diffuser".into(),
        ));
    }
    if aes256 {
        Ok((&fvek[0..32], &fvek[32..64]))
    } else {
        Ok((&fvek[0..16], &fvek[32..48]))
    }
}

/// Decrypt one 512-byte sector in place. `block_key` is the sector's byte offset.
pub fn decrypt_sector(
    aes_key: &[u8],
    tweak_key: &[u8],
    block_key: u64,
    sector: &mut [u8],
) -> Result<(), BitlockerError> {
    if sector.len() != 512 {
        return Err(BitlockerError::Malformed(
            "diffuser sector must be 512 bytes".into(),
        ));
    }
    let mut block = [0u8; 16];
    block[0..8].copy_from_slice(&block_key.to_le_bytes());

    let iv = ecb_encrypt(aes_key, &block);
    let mut sector_key = [0u8; 32];
    sector_key[0..16].copy_from_slice(&ecb_encrypt(tweak_key, &block));
    let mut block2 = block;
    block2[15] = 0x80;
    sector_key[16..32].copy_from_slice(&ecb_encrypt(tweak_key, &block2));

    cbc_decrypt(aes_key, &iv, sector);

    let mut w = [0u32; WORDS];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_le_bytes(sector[i * 4..i * 4 + 4].try_into().unwrap());
    }
    diffuser_b_decrypt(&mut w);
    diffuser_a_decrypt(&mut w);
    for (i, word) in w.iter().enumerate() {
        sector[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }

    for (i, byte) in sector.iter_mut().enumerate() {
        *byte ^= sector_key[i % 32];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_sector_and_short_fvek() {
        let mut small = [0u8; 256];
        assert!(decrypt_sector(&[0u8; 16], &[0u8; 16], 0, &mut small).is_err());
        assert!(split_fvek(&[0u8; 16], false).is_err());
    }

    #[test]
    fn diffuser_indices_stay_in_bounds() {
        // Exercise both diffusers on a full sector of words; must not panic and
        // must actually transform the data.
        let mut w = [0u32; WORDS];
        for (i, x) in w.iter_mut().enumerate() {
            *x = i as u32 + 1;
        }
        let orig = w;
        diffuser_b_decrypt(&mut w);
        diffuser_a_decrypt(&mut w);
        assert_ne!(w, orig);
    }
}
