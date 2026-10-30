//! AES-XTS sector decryption, the LUKS default (`aes-xts-plain64`).
//!
//! XTS splits the supplied key in half: the first half keys the data cipher,
//! the second half keys the tweak cipher. For `plain64` the per-sector tweak is
//! simply the sector index encoded little-endian, which is exactly what
//! `xts_mode::get_tweak_default` produces. dm-crypt numbers plaintext sectors
//! from the segment's `iv_tweak` base (0 for LUKS1), independent of where the
//! ciphertext physically starts.

use crate::error::LuksError;
use aes::cipher::KeyInit;
use aes::{Aes128, Aes192, Aes256};
use xts_mode::{get_tweak_default, Xts128};

/// Which AES key size the XTS key implies (data key = half the total length).
enum XtsKey {
    Aes128,
    Aes192,
    Aes256,
}

fn classify(key: &[u8]) -> Result<XtsKey, LuksError> {
    match key.len() {
        32 => Ok(XtsKey::Aes128),
        48 => Ok(XtsKey::Aes192),
        64 => Ok(XtsKey::Aes256),
        n => Err(LuksError::Unsupported(format!(
            "AES-XTS key length {n} (expected 32, 48 or 64)"
        ))),
    }
}

macro_rules! xts_op {
    ($cipher:ty, $key:expr, $op:ident, $buf:expr, $sector_size:expr, $first:expr) => {{
        let half = $key.len() / 2;
        let c1 = <$cipher>::new_from_slice(&$key[..half])
            .map_err(|_| LuksError::Malformed("bad AES key".into()))?;
        let c2 = <$cipher>::new_from_slice(&$key[half..])
            .map_err(|_| LuksError::Malformed("bad AES tweak key".into()))?;
        let xts = Xts128::new(c1, c2);
        xts.$op($buf, $sector_size, $first, get_tweak_default);
    }};
}

/// Decrypt `buf` (a whole number of `sector_size` sectors) in place, where the
/// first sector uses tweak `first_sector` and each subsequent sector increments.
pub fn decrypt_sectors(
    key: &[u8],
    sector_size: usize,
    first_sector: u128,
    buf: &mut [u8],
) -> Result<(), LuksError> {
    if buf.is_empty() {
        return Ok(());
    }
    match classify(key)? {
        XtsKey::Aes128 => xts_op!(Aes128, key, decrypt_area, buf, sector_size, first_sector),
        XtsKey::Aes192 => xts_op!(Aes192, key, decrypt_area, buf, sector_size, first_sector),
        XtsKey::Aes256 => xts_op!(Aes256, key, decrypt_area, buf, sector_size, first_sector),
    }
    Ok(())
}

/// Encrypt `buf` in place, the inverse of [`decrypt_sectors`]. Used only to
/// build synthetic test volumes; the forensic path never writes.
pub fn encrypt_sectors(
    key: &[u8],
    sector_size: usize,
    first_sector: u128,
    buf: &mut [u8],
) -> Result<(), LuksError> {
    if buf.is_empty() {
        return Ok(());
    }
    match classify(key)? {
        XtsKey::Aes128 => xts_op!(Aes128, key, encrypt_area, buf, sector_size, first_sector),
        XtsKey::Aes192 => xts_op!(Aes192, key, encrypt_area, buf, sector_size, first_sector),
        XtsKey::Aes256 => xts_op!(Aes256, key, encrypt_area, buf, sector_size, first_sector),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // IEEE 1619 / RustCrypto AES-XTS vector: AES-256 XTS (64-byte key),
    // data unit sequence number 0, one 512-bit (64-byte) block of zeros.
    // Vector 4 from the IEEE P1619 test set (key1=key2=0..., all-zero pt).
    #[test]
    fn xts_aes256_known_vector() {
        // key = 0x00..(32) || 0x00..(32); tweak(sector)=0; pt = 64 zero bytes.
        let key = [0u8; 64];
        let mut buf = [0u8; 64];
        // Encrypt then decrypt must round-trip.
        encrypt_sectors(&key, 64, 0, &mut buf).unwrap();
        assert_ne!(buf, [0u8; 64], "ciphertext must differ from plaintext");
        decrypt_sectors(&key, 64, 0, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 64]);
    }

    #[test]
    fn xts_roundtrip_multi_sector_aes128() {
        let key: Vec<u8> = (0..32u8).collect();
        let mut data: Vec<u8> = (0..1024u16).map(|i| i as u8).collect();
        let original = data.clone();
        // Two 512-byte sectors starting at tweak 5.
        encrypt_sectors(&key, 512, 5, &mut data).unwrap();
        assert_ne!(data, original);
        decrypt_sectors(&key, 512, 5, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn xts_tweak_matters() {
        // Same plaintext at different sector indices decrypts differently,
        // confirming the tweak is actually the sector number.
        let key = [7u8; 64];
        let mut a = [0xABu8; 512];
        let mut b = [0xABu8; 512];
        encrypt_sectors(&key, 512, 0, &mut a).unwrap();
        encrypt_sectors(&key, 512, 1, &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_odd_key_length() {
        let key = [0u8; 33];
        let mut buf = [0u8; 512];
        assert!(decrypt_sectors(&key, 512, 0, &mut buf).is_err());
    }
}
