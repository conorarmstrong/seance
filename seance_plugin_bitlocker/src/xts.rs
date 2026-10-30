//! AES-XTS sector decryption for BitLocker (Windows 10+ `AES-XTS 128/256`).
//!
//! The FVEK is laid out as `data_key || tweak_key` (16+16 for XTS-128, 32+32 for
//! XTS-256). The per-sector tweak is the sector index encoded little-endian,
//! which is exactly `xts_mode::get_tweak_default`.

use crate::error::BitlockerError;
use aes::cipher::KeyInit;
use aes::{Aes128, Aes256};
use xts_mode::{get_tweak_default, Xts128};

/// Decrypt `buf` (a whole number of `sector_size` sectors) in place, treating
/// the first sector as index `first_sector`.
pub fn decrypt_sectors(
    fvek: &[u8],
    xts256: bool,
    sector_size: usize,
    first_sector: u128,
    buf: &mut [u8],
) -> Result<(), BitlockerError> {
    let bad = |_| BitlockerError::Malformed("bad AES key".into());
    if xts256 {
        if fvek.len() < 64 {
            return Err(BitlockerError::Malformed(
                "FVEK too short for XTS-256".into(),
            ));
        }
        let data = Aes256::new_from_slice(&fvek[0..32]).map_err(bad)?;
        let tweak = Aes256::new_from_slice(&fvek[32..64]).map_err(bad)?;
        Xts128::<Aes256>::new(data, tweak).decrypt_area(
            buf,
            sector_size,
            first_sector,
            get_tweak_default,
        );
    } else {
        if fvek.len() < 32 {
            return Err(BitlockerError::Malformed(
                "FVEK too short for XTS-128".into(),
            ));
        }
        let data = Aes128::new_from_slice(&fvek[0..16]).map_err(bad)?;
        let tweak = Aes128::new_from_slice(&fvek[16..32]).map_err(bad)?;
        Xts128::<Aes128>::new(data, tweak).decrypt_area(
            buf,
            sector_size,
            first_sector,
            get_tweak_default,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encrypt with XTS (the inverse of `decrypt_sectors`) so we can prove a
    /// round-trip: what we decrypt is exactly what was encrypted.
    fn encrypt_sectors(fvek: &[u8], sector_size: usize, first_sector: u128, buf: &mut [u8]) {
        let data = Aes128::new_from_slice(&fvek[0..16]).unwrap();
        let tweak = Aes128::new_from_slice(&fvek[16..32]).unwrap();
        Xts128::<Aes128>::new(data, tweak).encrypt_area(
            buf,
            sector_size,
            first_sector,
            get_tweak_default,
        );
    }

    #[test]
    fn xts128_round_trip_across_sectors() {
        let fvek: Vec<u8> = (0u8..32).collect();
        let plaintext: Vec<u8> = (0..1024).map(|i| (i * 7 % 251) as u8).collect();
        let mut buf = plaintext.clone();

        // Encrypt two 512-byte sectors starting at sector 5, then decrypt back.
        encrypt_sectors(&fvek, 512, 5, &mut buf);
        assert_ne!(buf, plaintext, "encryption must change the data");
        decrypt_sectors(&fvek, false, 512, 5, &mut buf).unwrap();
        assert_eq!(buf, plaintext, "XTS decrypt must invert XTS encrypt");
    }

    #[test]
    fn short_fvek_is_rejected() {
        let mut buf = [0u8; 512];
        assert!(decrypt_sectors(&[0u8; 16], false, 512, 0, &mut buf).is_err());
    }
}
