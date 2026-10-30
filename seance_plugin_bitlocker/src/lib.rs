#![forbid(unsafe_code)]
//! BitLocker (Windows FVE) volume unlocking for Séance.
//!
//! Turns an encrypted BitLocker volume plus a credential into recovered keys and
//! — for the modern AES-XTS ciphers — a plaintext [`DataSource`] the rest of the
//! pipeline can read transparently.
//!
//! # What is validated
//!
//! Detection, FVE metadata parsing, the password key-derivation, and the AES-CCM
//! unwrap of the VMK and FVEK were validated byte-for-byte against a real Windows
//! BitLocker-To-Go volume (`test_data/bdetogo.raw`, password `bde-TEST`): the
//! recovered FVEK matches and every AES-CCM MAC verifies, which authenticates the
//! whole key hierarchy against genuine Windows crypto.
//!
//! # Scope
//!
//! - **Key recovery** (VMK + FVEK) from a user password works for every cipher.
//! - **Decryption** is provided for **AES-XTS 128/256** (Windows 10+) and for
//!   **AES-CBC + Elephant diffuser 128/256** (Vista/7/8). The diffuser transform
//!   was validated byte-for-byte against the real `bdetogo.raw` volume (empty
//!   clusters → zeros; the relocated FAT boot record → a valid 0x55AA sector).
//!   Plain AES-CBC without the diffuser (0x8002/0x8003) is detected and its keys
//!   recovered, but its sector decryption is not yet wired.

mod crypto;
/// The sector size this build's XTS path decrypts at.
///
/// The XTS tweak is per-sector, so the size is not a detail: a 4Kn volume
/// decrypted as if it were 512n produces bytes for every sector and correct
/// bytes for none. Nothing downstream can distinguish that from a volume
/// genuinely full of noise, and a carver will produce "recovered files" from
/// it. A volume declaring anything else is reported as detected and left
/// undecrypted (BUG-061).
const SUPPORTED_SECTOR_SIZE: usize = 512;

mod diffuser;
mod error;
mod fve;
pub mod module;
mod source;
mod xts;

use seance_core::data_source::DataSource;
use std::sync::Arc;

pub use crypto::{Credential, EncryptionMethod};
pub use error::BitlockerError;
pub use fve::is_bitlocker;
pub use module::BitlockerDecryptor;
pub use source::{BitlockerDiffuserDataSource, BitlockerVolumeSource, BitlockerXtsDataSource};

/// What a BitLocker volume can be made to say about itself with **no
/// credential at all**.
///
/// BitLocker leaves its three FVE metadata blocks unencrypted, so the cipher,
/// the volume identifier and the list of key protectors are readable on any
/// locked volume. That matters because the common case in casework is a volume
/// nobody has the key to, and "an AES-XTS-256 volume with a recovery-password
/// protector is present and was not opened" is a finding; silence is not.
pub struct BitlockerDetection {
    pub encryption_method: EncryptionMethod,
    /// FVE volume identifier, as stored (mixed-endian).
    pub volume_guid: [u8; 16],
    /// Bytes per sector from the VBR's BPB.
    pub bytes_per_sector: u16,
    /// Human labels for the volume's key protectors, in metadata order — what
    /// an examiner would have to obtain to open this volume.
    pub key_protectors: Vec<String>,
}

impl BitlockerDetection {
    /// The volume identifier in the usual GUID text form.
    ///
    /// The first three fields are stored little-endian and the last two big-,
    /// exactly as Microsoft writes a GUID; rendering it as a flat hex string
    /// would produce an identifier that matches nothing an examiner can search
    /// for in `manage-bde` output or a recovery-key escrow record.
    pub fn volume_identifier(&self) -> String {
        let g = &self.volume_guid;
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
            u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
            u16::from_le_bytes([g[4], g[5]]),
            u16::from_le_bytes([g[6], g[7]]),
            g[8],
            g[9],
            g[10..16]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }
}

/// Describe a BitLocker volume without unlocking it.
///
/// `None` when the volume is not BitLocker, or when none of its three metadata
/// blocks could be read — which is a fact about the image, not a licence to
/// treat the volume as unencrypted. Callers that have already established the
/// volume IS BitLocker (via [`is_bitlocker`]) must report it either way.
pub fn describe_bitlocker(volume: &dyn DataSource) -> Option<BitlockerDetection> {
    let d = fve::describe(volume)?;
    Some(BitlockerDetection {
        encryption_method: EncryptionMethod::from_raw(d.encryption_method),
        volume_guid: d.volume_guid,
        bytes_per_sector: d.bytes_per_sector,
        key_protectors: d
            .protector_types
            .into_iter()
            .map(fve::protector_label)
            .collect(),
    })
}

/// The result of unlocking a BitLocker volume.
pub struct UnlockedVolume {
    pub encryption_method: EncryptionMethod,
    pub volume_guid: [u8; 16],
    /// The recovered full-volume encryption key, wiped when dropped
    /// (HUNT-254).
    pub fvek: zeroize::Zeroizing<Vec<u8>>,
    /// A decrypting view of the volume, present only for the AES-XTS ciphers.
    /// `None` means the keys were recovered but this cipher is not decryptable
    /// yet (the caller can still export `fvek`).
    pub decrypting_source: Option<Arc<dyn DataSource>>,
}

/// Unlock a BitLocker volume with a credential, recovering its keys and (for
/// AES-XTS) a decrypting data source.
pub fn unlock_bitlocker(
    volume: Arc<dyn DataSource>,
    credential: &Credential,
) -> Result<UnlockedVolume, BitlockerError> {
    let meta = fve::parse(volume.as_ref())?;

    // Try each VMK protector; the AES-CCM MAC authenticates a correct credential.
    let mut vmk_key = None;
    for protector in &meta.vmk_protectors {
        let unwrap_key = crypto::derive_vmk_unwrap_key(credential, &protector.salt)?;
        if let Ok(plaintext) = crypto::ccm_unwrap(&unwrap_key, &protector.aes_ccm) {
            let plaintext = zeroize::Zeroizing::new(plaintext);
            if let Some((_method, key)) = fve::extract_key(&plaintext) {
                vmk_key = Some(zeroize::Zeroizing::new(key));
                break;
            }
        }
    }
    let vmk_key = vmk_key.ok_or(BitlockerError::BadCredential)?;

    // Unwrap the FVEK with the recovered VMK.
    let fvek_plaintext = zeroize::Zeroizing::new(crypto::ccm_unwrap(&vmk_key, &meta.fvek_aes_ccm)?);
    let (_fvek_method, fvek) = fve::extract_key(&fvek_plaintext)
        .ok_or_else(|| BitlockerError::Malformed("no FVEK key in plaintext".into()))?;
    let fvek = zeroize::Zeroizing::new(fvek);

    let encryption_method = EncryptionMethod::from_raw(meta.encryption_method);
    // A sector size this build cannot honour. Zero means the VBR did not carry
    // one, which is equally not a size to decrypt on.
    let sector_size_unsupported =
        meta.bytes_per_sector != SUPPORTED_SECTOR_SIZE as u16 && encryption_method.is_xts();
    if sector_size_unsupported {
        tracing::warn!(
            "BitLocker volume declares {} bytes per sector; this build decrypts XTS volumes at \
             {} only, so the volume is reported as detected and NOT decrypted. Decrypting on the \
             wrong sector size would produce plausible-looking bytes that are wrong throughout.",
            meta.bytes_per_sector,
            SUPPORTED_SECTOR_SIZE
        );
    }
    let cipher_source: Option<Arc<dyn DataSource>> = if sector_size_unsupported {
        None
    } else if encryption_method.is_xts() {
        let xts256 = encryption_method == EncryptionMethod::AesXts256;
        Some(Arc::new(source::BitlockerXtsDataSource::new(
            Arc::clone(&volume),
            fvek.clone(),
            xts256,
            SUPPORTED_SECTOR_SIZE,
        )))
    } else if matches!(
        encryption_method,
        EncryptionMethod::AesCbc128Diffuser | EncryptionMethod::AesCbc256Diffuser
    ) {
        let aes256 = encryption_method == EncryptionMethod::AesCbc256Diffuser;
        let (aes_key, tweak_key) = diffuser::split_fvek(&fvek, aes256)?;
        Some(Arc::new(source::BitlockerDiffuserDataSource::new(
            Arc::clone(&volume),
            aes_key.to_vec(),
            tweak_key.to_vec(),
        )))
    } else {
        // Plain AES-CBC without the diffuser (0x8002/0x8003) is detected and its
        // keys recovered, but sector decryption is not yet wired.
        None
    };

    // Present the volume as its filesystem believes it is: boot sectors back
    // at the front, and the unencrypted FVE metadata regions passed through
    // rather than ciphered into noise.
    //
    // Decryption alone is not enough to hand the result to a filesystem parser:
    // BitLocker's own VBR sits at sector 0 and the real one is relocated, so a
    // purely decrypting view has noise where the boot sector should be. NTFS
    // parsing then fails on a volume that was fully recovered, and fails in the
    // way that looks like an unformatted disk rather than like an error.
    let (header_offset, header_len) = meta.volume_header;
    let regions = meta.metadata_regions.clone();
    let decrypting_source: Option<Arc<dyn DataSource>> = cipher_source.map(|s| {
        if header_len == 0 && regions.is_empty() {
            s
        } else {
            Arc::new(source::BitlockerVolumeSource::new(
                s,
                Arc::clone(&volume),
                header_offset,
                header_len,
                regions,
            )) as Arc<dyn DataSource>
        }
    });

    Ok(UnlockedVolume {
        encryption_method,
        volume_guid: meta.volume_guid,
        fvek,
        decrypting_source,
    })
}
