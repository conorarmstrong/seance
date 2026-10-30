//! Hash-spec dispatch: PBKDF2 key derivation and one-shot digests.
//!
//! LUKS names its hash as a free-form string ("sha1", "sha256", "sha512").
//! We map it to a concrete RustCrypto digest and drive PBKDF2 (LUKS1 slot keys
//! and MK-digest, LUKS2 pbkdf2 keyslots and digests) as well as the raw digest
//! used by the anti-forensic diffuser.

use crate::error::LuksError;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

/// A hash algorithm named by a LUKS header/metadata field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashSpec {
    Sha1,
    Sha256,
    Sha512,
}

impl HashSpec {
    /// Parse a LUKS hash-spec string. Case-insensitive.
    pub fn parse(name: &str) -> Result<Self, LuksError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            other => Err(LuksError::Unsupported(format!("hash-spec '{other}'"))),
        }
    }

    /// Digest output length in bytes.
    pub fn digest_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// One-shot digest of `data`, used by the anti-forensic diffuser.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// PBKDF2-HMAC key derivation with this hash into `out`.
    pub fn pbkdf2(self, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
        // iterations of 0 is invalid per RFC 8018; treat as 1 to avoid a panic
        // in the underlying crate on malformed headers.
        let iters = iterations.max(1);
        match self {
            Self::Sha1 => pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, iters, out),
            Self::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iters, out),
            Self::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iters, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_hashes() {
        assert_eq!(HashSpec::parse("sha256").unwrap(), HashSpec::Sha256);
        assert_eq!(HashSpec::parse("SHA1").unwrap(), HashSpec::Sha1);
        assert_eq!(HashSpec::parse(" sha512 ").unwrap(), HashSpec::Sha512);
        assert!(HashSpec::parse("whirlpool").is_err());
    }

    // RFC 6070 PBKDF2-HMAC-SHA1 test vector.
    #[test]
    fn pbkdf2_sha1_rfc6070() {
        let mut out = [0u8; 20];
        HashSpec::Sha1.pbkdf2(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out,
            [
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
                0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
            ]
        );
    }

    // RFC 6070 vector with 2 iterations.
    #[test]
    fn pbkdf2_sha1_rfc6070_two_iters() {
        let mut out = [0u8; 20];
        HashSpec::Sha1.pbkdf2(b"password", b"salt", 2, &mut out);
        assert_eq!(
            out,
            [
                0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
                0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
            ]
        );
    }
}
