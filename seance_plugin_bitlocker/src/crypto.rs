//! BitLocker key derivation and AES-CCM key unwrapping.
//!
//! The password path and the AES-CCM unwrap were validated byte-for-byte against
//! a real Windows volume (`test_data/bdetogo.raw`, password `bde-TEST`): the
//! derived key unwraps the VMK and then the FVEK with the AES-CCM MAC verifying,
//! which authenticates the whole chain.

use crate::error::BitlockerError;
use aes::Aes256;
use ccm::aead::generic_array::GenericArray;
use ccm::aead::{Aead, KeyInit};
use ccm::consts::{U12, U16};
use ccm::Ccm;
use sha2::{Digest, Sha256};

type AesCcm = Ccm<Aes256, U16, U12>;

/// BitLocker's key-stretch iteration count (2^20).
const STRETCH_ITERATIONS: u64 = 0x100000;

/// A user-supplied unlock secret. Its text is zeroed when it drops.
pub enum Credential {
    /// A user password (validated end-to-end against a real volume).
    Password(String),
    /// A 48-digit recovery password, e.g. "111111-222222-...", validated
    /// end-to-end against the Windows 11 XTS-AES-256 corpus volume.
    RecoveryKey(String),
}

impl Credential {
    /// The credential-kind name the audit log and the unlocked record use.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Credential::Password(_) => "bitlocker_password",
            Credential::RecoveryKey(_) => "bitlocker_recovery_password",
        }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Credential::Password(s) | Credential::RecoveryKey(s) => s.zeroize(),
        }
    }
}

/// BitLocker full-volume encryption methods (FVE `encryption_method`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    AesCbc128Diffuser,
    AesCbc256Diffuser,
    AesCbc128,
    AesCbc256,
    AesXts128,
    AesXts256,
    Unknown(u16),
}

impl EncryptionMethod {
    pub fn from_raw(v: u16) -> Self {
        match v {
            0x8000 => Self::AesCbc128Diffuser,
            0x8001 => Self::AesCbc256Diffuser,
            0x8002 => Self::AesCbc128,
            0x8003 => Self::AesCbc256,
            0x8004 => Self::AesXts128,
            0x8005 => Self::AesXts256,
            other => Self::Unknown(other),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::AesCbc128Diffuser => "AES-CBC 128-bit + Elephant diffuser".into(),
            Self::AesCbc256Diffuser => "AES-CBC 256-bit + Elephant diffuser".into(),
            Self::AesCbc128 => "AES-CBC 128-bit".into(),
            Self::AesCbc256 => "AES-CBC 256-bit".into(),
            Self::AesXts128 => "AES-XTS 128-bit".into(),
            Self::AesXts256 => "AES-XTS 256-bit".into(),
            Self::Unknown(v) => format!("unknown (0x{v:04x})"),
        }
    }

    /// True for the AES-XTS ciphers this crate can decrypt (Windows 10+).
    pub fn is_xts(&self) -> bool {
        matches!(self, Self::AesXts128 | Self::AesXts256)
    }
}

/// Hash the credential into the 32-byte input to the stretch KDF.
///
/// **The two credential kinds are hashed differently, and this is not
/// symmetrical for the sake of it.**
///
/// A user password is UTF-16LE text of arbitrary length, and BitLocker hashes
/// it *twice* with SHA-256. A recovery password is not text at all: the 48
/// digits decode to exactly 16 bytes of key material, and BitLocker hashes
/// those *once*.
///
/// Applying the password's double hash to a recovery key produces a
/// well-formed 32-byte value that is simply the wrong key — the AES-CCM MAC
/// then fails and the volume is reported as "bad credential", indistinguishable
/// from a genuinely wrong recovery password. Verified against a real Windows 11
/// 25H2 volume, where only the single hash authenticates.
fn credential_prehash(cred: &Credential) -> Result<[u8; 32], BitlockerError> {
    Ok(match cred {
        Credential::Password(p) => {
            let mut utf16 = p
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>();
            let digest: [u8; 32] = Sha256::digest(Sha256::digest(&utf16)).into();
            // The UTF-16 copy is the password in another encoding.
            zeroize::Zeroize::zeroize(&mut utf16);
            digest
        }
        Credential::RecoveryKey(k) => Sha256::digest(parse_recovery_key(k)?).into(),
    })
}

/// BitLocker's key stretch: 2^20 iterations of SHA-256 over an 88-byte block of
/// `last_hash(32) | prehash(32) | salt(16) | counter(8)`.
pub fn stretch(prehash: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    let mut buf = [0u8; 88];
    buf[32..64].copy_from_slice(prehash);
    buf[64..80].copy_from_slice(salt);
    for count in 0..STRETCH_ITERATIONS {
        buf[80..88].copy_from_slice(&count.to_le_bytes());
        let h = Sha256::digest(buf);
        buf[0..32].copy_from_slice(&h);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[0..32]);
    out
}

/// Derive the VMK-unwrap key for a protector: stretch the credential's prehash
/// with the protector's salt.
pub fn derive_vmk_unwrap_key(
    cred: &Credential,
    salt: &[u8; 16],
) -> Result<[u8; 32], BitlockerError> {
    Ok(stretch(&credential_prehash(cred)?, salt))
}

/// AES-CCM decrypt a BitLocker blob (`nonce(12) | MAC(16) | ciphertext`). Returns
/// the plaintext, or an error if the MAC does not verify (wrong key).
pub fn ccm_unwrap(key: &[u8], blob: &[u8]) -> Result<Vec<u8>, BitlockerError> {
    if blob.len() < 28 {
        return Err(BitlockerError::Malformed("AES-CCM blob too short".into()));
    }
    let nonce = &blob[0..12];
    let mac = &blob[12..28];
    let ct = &blob[28..];
    // The `ccm` crate expects the tag appended to the ciphertext.
    let mut input = Vec::with_capacity(ct.len() + 16);
    input.extend_from_slice(ct);
    input.extend_from_slice(mac);

    let cipher =
        AesCcm::new_from_slice(key).map_err(|_| BitlockerError::Malformed("bad CCM key".into()))?;
    cipher
        .decrypt(GenericArray::from_slice(nonce), input.as_ref())
        .map_err(|_| BitlockerError::BadCredential)
}

/// Parse a 48-digit BitLocker recovery password ("dddddd-dddddd-..." × 8) into
/// its 16-byte key. Each 6-digit group must be divisible by 11 and, divided by
/// 11, fit in 16 bits — the documented integrity rules.
pub fn parse_recovery_key(s: &str) -> Result<[u8; 16], BitlockerError> {
    let groups: Vec<&str> = s.split('-').collect();
    if groups.len() != 8 {
        return Err(BitlockerError::InvalidRecoveryKey(
            "expected 8 groups of 6 digits".into(),
        ));
    }
    let mut key = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        if g.len() != 6 || !g.bytes().all(|c| c.is_ascii_digit()) {
            return Err(BitlockerError::InvalidRecoveryKey(format!(
                "group {} is not 6 digits",
                i + 1
            )));
        }
        let n: u32 = g
            .parse()
            .map_err(|_| BitlockerError::InvalidRecoveryKey("non-numeric group".into()))?;
        if !n.is_multiple_of(11) {
            return Err(BitlockerError::InvalidRecoveryKey(format!(
                "group {} is not divisible by 11",
                i + 1
            )));
        }
        let v = n / 11;
        if v > 0xffff {
            return Err(BitlockerError::InvalidRecoveryKey(format!(
                "group {} out of range",
                i + 1
            )));
        }
        key[i * 2..i * 2 + 2].copy_from_slice(&(v as u16).to_le_bytes());
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_key_parses_valid_and_rejects_invalid() {
        // 11 and 22 are divisible by 11; build a syntactically valid 48-digit key.
        let good = "000011-000022-000033-000044-000055-000066-000077-000088";
        let key = parse_recovery_key(good).unwrap();
        // First group 11/11 = 1 -> LE u16 0x0001.
        assert_eq!(&key[0..2], &[0x01, 0x00]);

        // Wrong group count.
        assert!(parse_recovery_key("000011-000022").is_err());
        // Not divisible by 11.
        assert!(
            parse_recovery_key("000010-000022-000033-000044-000055-000066-000077-000088").is_err()
        );
        // Non-digit.
        assert!(
            parse_recovery_key("00001A-000022-000033-000044-000055-000066-000077-000088").is_err()
        );
    }

    #[test]
    fn encryption_method_classification() {
        assert_eq!(
            EncryptionMethod::from_raw(0x8000),
            EncryptionMethod::AesCbc128Diffuser
        );
        assert!(EncryptionMethod::from_raw(0x8004).is_xts());
        assert!(!EncryptionMethod::from_raw(0x8000).is_xts());
        assert_eq!(
            EncryptionMethod::from_raw(0x1234),
            EncryptionMethod::Unknown(0x1234)
        );
    }
}
