//! Cryptographic support for encrypted iOS backups
//!
//! iOS backup encryption uses a multi-layer key hierarchy:
//! 1. Password → double PBKDF2 → passcode key
//! 2. Passcode key unwraps class keys from the keybag (RFC 3394 AES Key Wrap)
//! 3. Class keys decrypt per-file keys stored in Manifest.db
//! 4. Per-file keys decrypt individual backup files (AES-256-CBC, zero IV, PKCS#7)
//!
//! The keybag is a TLV binary blob in Manifest.plist under "BackupKeyBag".
//!
//! References:
//! - <https://github.com/jsharkey/iPhone-dataprotection>
//! - <https://github.com/horrorho/InflatableDonkey>
//! - Apple iOS Security Guide

use aes::cipher::BlockDecrypt;
use aes::{Aes256, Block};
use aes_kw::KekAes256;
use anyhow::{anyhow, Result};
use cbc::cipher::{BlockDecryptMut, KeyInit, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use seance_core::data_source::DataSource;
use sha1::Sha1;
use sha2::Sha256;
use std::path::PathBuf;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Known TLV tag identifiers in the keybag binary format.
/// Tags are 4-byte ASCII strings read as big-endian u32.
const TAG_UUID: u32 = u32::from_be_bytes(*b"UUID");
const TAG_SALT: u32 = u32::from_be_bytes(*b"SALT");
const TAG_ITER: u32 = u32::from_be_bytes(*b"ITER");
const TAG_DPSL: u32 = u32::from_be_bytes(*b"DPSL");
const TAG_DPIC: u32 = u32::from_be_bytes(*b"DPIC");
const TAG_CLAS: u32 = u32::from_be_bytes(*b"CLAS");
const TAG_WRAP: u32 = u32::from_be_bytes(*b"WRAP");
const TAG_WPKY: u32 = u32::from_be_bytes(*b"WPKY");
const TAG_KTYP: u32 = u32::from_be_bytes(*b"KTYP");

/// Wrap type bit indicating the key is wrapped with the passcode key
const WRAP_PASSCODE: u32 = 2;
/// Wrap type bit indicating the key is (also) wrapped with the device's
/// hardware key (the UID-derived key 0x835), which a backup does not carry.
/// A class with this bit set cannot be unlocked from a backup, whatever the
/// password: the passcode layer alone yields an intermediate value, not the
/// class key.
pub const WRAP_DEVICE: u32 = 1;

/// Whether a keybag class key can be used, once the keybag is unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassKeyState {
    /// Passcode-wrapped only, and unwrapped: the class key is held.
    Usable,
    /// Wrapped under the device's hardware key as well (`WRAP & 1`): no
    /// backup can open it.
    DeviceBound,
    /// Not unwrapped (the keybag is still locked, or the class is wrapped by
    /// neither known layer).
    NotUnwrapped,
}

impl ClassKeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            ClassKeyState::Usable => "usable",
            ClassKeyState::DeviceBound => "device_bound",
            ClassKeyState::NotUnwrapped => "not_unwrapped",
        }
    }
}

/// Parsed iOS backup keybag containing encryption parameters and class keys.
#[derive(Debug, Clone)]
pub struct Keybag {
    pub uuid: Vec<u8>,
    pub salt: Vec<u8>,
    pub iter: u32,
    /// Double PBKDF2 salt (iOS 10.2+), None for legacy backups
    pub dpsl: Option<Vec<u8>>,
    /// Double PBKDF2 iterations (iOS 10.2+), None for legacy backups
    pub dpic: Option<u32>,
    pub class_keys: Vec<ClassKey>,
}

/// A single class key entry from the keybag.
///
/// The unwrapped key is zeroed when the entry drops and is never printed by
/// `Debug` (BUG-026: an unlocked keybag may now be held for re-reading after
/// ingest, so its keys must not reach a log line).
#[derive(Clone)]
pub struct ClassKey {
    pub class: u32,
    pub wrap_type: u32,
    pub wrapped_key: Vec<u8>,
    pub unwrapped_key: Option<Vec<u8>>,
}

impl ClassKey {
    /// This class key's state. A device-bound class is never usable from a
    /// backup, even after its passcode layer checked out.
    pub fn state(&self) -> ClassKeyState {
        if self.wrap_type & WRAP_DEVICE != 0 {
            ClassKeyState::DeviceBound
        } else if self.unwrapped_key.is_some() {
            ClassKeyState::Usable
        } else {
            ClassKeyState::NotUnwrapped
        }
    }
}

impl std::fmt::Debug for ClassKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClassKey")
            .field("class", &self.class)
            .field("wrap_type", &self.wrap_type)
            .field("wrapped_key_len", &self.wrapped_key.len())
            .field("state", &self.state())
            .field(
                "unwrapped_key",
                &self.unwrapped_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for ClassKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(k) = self.unwrapped_key.as_mut() {
            k.zeroize();
        }
    }
}

/// Parse a keybag from its TLV binary representation.
///
/// Format: repeated (4-byte BE tag, 4-byte BE length, N-byte value).
/// Global tags (UUID, SALT, ITER, DPSL, DPIC) come first, then per-class
/// triplets of (CLAS, WRAP, WPKY).
pub fn parse_keybag(data: &[u8]) -> Result<Keybag> {
    let mut uuid = Vec::new();
    let mut salt = Vec::new();
    let mut iter: u32 = 0;
    let mut dpsl: Option<Vec<u8>> = None;
    let mut dpic: Option<u32> = None;
    let mut class_keys: Vec<ClassKey> = Vec::new();

    // Temp state for building class key entries
    let mut current_class: Option<u32> = None;
    let mut current_wrap: Option<u32> = None;

    let mut pos = 0;
    while pos + 8 <= data.len() {
        let tag = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let length =
            u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                as usize;
        pos += 8;

        if pos + length > data.len() {
            return Err(anyhow!(
                "Keybag TLV truncated: need {} bytes at offset {}, have {}",
                length,
                pos,
                data.len() - pos
            ));
        }

        let value = &data[pos..pos + length];
        pos += length;

        match tag {
            TAG_UUID => uuid = value.to_vec(),
            TAG_SALT => salt = value.to_vec(),
            TAG_ITER => {
                if value.len() >= 4 {
                    iter = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                }
            }
            TAG_DPSL => dpsl = Some(value.to_vec()),
            TAG_DPIC => {
                if value.len() >= 4 {
                    dpic = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                }
            }
            TAG_CLAS => {
                // A new CLAS tag starts a new class key entry.
                // First, finalize any previous entry that had class + wrap but no WPKY yet
                // (shouldn't happen in valid keybags, but be safe).
                if value.len() >= 4 {
                    current_class =
                        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                    current_wrap = None; // reset for this class
                }
            }
            TAG_WRAP => {
                if value.len() >= 4 {
                    current_wrap =
                        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                }
            }
            TAG_WPKY => {
                // WPKY completes a class key entry
                if let Some(class) = current_class {
                    class_keys.push(ClassKey {
                        class,
                        wrap_type: current_wrap.unwrap_or(0),
                        wrapped_key: value.to_vec(),
                        unwrapped_key: None,
                    });
                    current_class = None;
                    current_wrap = None;
                }
            }
            TAG_KTYP => { /* key type — informational, skip */ }
            _ => { /* unknown tag, skip */ }
        }
    }

    if salt.is_empty() {
        return Err(anyhow!("Keybag missing SALT"));
    }
    if iter == 0 {
        return Err(anyhow!("Keybag missing ITER or ITER is zero"));
    }

    Ok(Keybag {
        uuid,
        salt,
        iter,
        dpsl,
        dpic,
        class_keys,
    })
}

/// Derive the passcode key from a password and keybag parameters.
///
/// iOS 10.2+ (when DPSL and DPIC are present):
///   Round 1: PBKDF2-HMAC-SHA256(password, DPSL, DPIC) → 32 bytes
///   Round 2: PBKDF2-HMAC-SHA1(round1, SALT, ITER) → 32 bytes
///
/// Legacy (no DPSL):
///   Single round: PBKDF2-HMAC-SHA1(password, SALT, ITER) → 32 bytes
pub fn derive_passcode_key(password: &str, keybag: &Keybag) -> Result<[u8; 32]> {
    let key = if let (Some(dpsl), Some(dpic)) = (&keybag.dpsl, keybag.dpic) {
        // iOS 10.2+ double PBKDF2
        let mut round1 = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), dpsl, dpic, &mut round1);

        let mut round2 = [0u8; 32];
        pbkdf2_hmac::<Sha1>(&round1, &keybag.salt, keybag.iter, &mut round2);
        round2
    } else {
        // Legacy single PBKDF2
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha1>(password.as_bytes(), &keybag.salt, keybag.iter, &mut key);
        key
    };

    Ok(key)
}

/// A passcode-wrapped class key failed RFC 3394's integrity check under the
/// derived passcode key. The check cannot tell a wrong password from a wrapped
/// key whose bytes are corrupt: both leave the integrity value wrong
/// (`SEC-204`).
#[derive(Debug)]
pub struct ClassKeyIntegrityFailed {
    pub class: u32,
}

impl std::fmt::Display for ClassKeyIntegrityFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Incorrect backup password or corrupted keybag \
             (RFC 3394 integrity check failed for class {})",
            self.class
        )
    }
}

impl std::error::Error for ClassKeyIntegrityFailed {}

/// Unwrap all class keys in the keybag using the derived passcode key.
///
/// Uses RFC 3394 AES-256 Key Unwrap for each class key that has the
/// passcode wrap bit set (WRAP & 2), and returns how many it unwrapped — `0`
/// means the password was never tested. An integrity failure is a typed
/// [`ClassKeyIntegrityFailed`] (wrong password *or* corrupt wrapped key); a
/// wrapped key that is not a valid RFC 3394 length is a malformed keybag, a
/// plain error that says nothing about the password.
pub fn unwrap_class_keys(keybag: &mut Keybag, passcode_key: &[u8; 32]) -> Result<usize> {
    let kek = KekAes256::from(*passcode_key);
    let mut unwrapped_count = 0usize;

    for ck in &mut keybag.class_keys {
        if ck.wrap_type & WRAP_PASSCODE == 0 {
            // Not wrapped with passcode — skip
            continue;
        }

        match kek.unwrap_vec(&ck.wrapped_key) {
            Ok(unwrapped) => {
                let mut unwrapped = zeroize::Zeroizing::new(unwrapped);
                // The passcode layer checked out, so the password was tested.
                unwrapped_count += 1;
                if ck.wrap_type & WRAP_DEVICE != 0 {
                    // Device-bound (WRAP=3): what the passcode layer yields is
                    // still wrapped under the device's hardware key. It is not
                    // the class key and is not kept (dropped and zeroed here).
                    ck.unwrapped_key = None;
                } else {
                    ck.unwrapped_key = Some(std::mem::take(&mut *unwrapped));
                }
            }
            Err(aes_kw::Error::IntegrityCheckFailed) => {
                return Err(anyhow::Error::new(ClassKeyIntegrityFailed {
                    class: ck.class,
                }));
            }
            Err(e) => {
                return Err(anyhow!(
                    "malformed keybag: the wrapped key for class {} ({} bytes) is not an \
                     RFC 3394 wrapped key ({e:?})",
                    ck.class,
                    ck.wrapped_key.len()
                ));
            }
        }
    }

    Ok(unwrapped_count)
}

/// Strip PKCS#7 padding from decrypted data.
///
/// Validates that the padding byte value is 1..=16 and that all padding
/// bytes match, then truncates the vector.
pub fn strip_pkcs7_padding(data: &mut Vec<u8>) -> Result<()> {
    if data.is_empty() {
        return Err(anyhow!("Cannot strip PKCS#7 padding from empty data"));
    }

    let pad_byte = *data.last().unwrap();
    let pad_len = pad_byte as usize;

    if pad_len == 0 || pad_len > 16 || pad_len > data.len() {
        return Err(anyhow!("Invalid PKCS#7 padding byte: {}", pad_byte));
    }

    // Verify all padding bytes match
    for &b in &data[data.len() - pad_len..] {
        if b != pad_byte {
            return Err(anyhow!("Invalid PKCS#7 padding: inconsistent bytes"));
        }
    }

    data.truncate(data.len() - pad_len);
    Ok(())
}

/// Validate the PKCS#7 padding in a decrypted final 16-byte block and return the
/// pad length. Fails closed (returns `Err`) on an out-of-range pad byte or
/// inconsistent pad bytes — the signature of a wrong key or corrupt ciphertext —
/// so the caller never treats the block's tail as real plaintext.
fn validate_pkcs7_final_block(block: &[u8]) -> Result<u64> {
    let pad = *block.last().ok_or_else(|| anyhow!("empty final block"))? as usize;
    if !(1..=16).contains(&pad) || pad > block.len() {
        return Err(anyhow!(
            "Invalid PKCS#7 padding byte {} in final block \
             (wrong file key or corrupt ciphertext)",
            pad
        ));
    }
    if block[block.len() - pad..]
        .iter()
        .any(|&b| b as usize != pad)
    {
        return Err(anyhow!(
            "Inconsistent PKCS#7 padding in final block \
             (wrong file key or corrupt ciphertext)"
        ));
    }
    Ok(pad as u64)
}

/// The class key for `protection_class`, if the unlocked keybag holds a
/// usable one. A device-bound class (`WRAP & 1`) is refused by name: a backup
/// cannot open it with any password.
pub fn usable_class_key(keybag: &Keybag, protection_class: u32) -> Result<&[u8]> {
    get_class_key(keybag, protection_class)
}

/// Each class in the keybag with its state, in keybag order. No key bytes.
pub fn class_key_states(keybag: &Keybag) -> Vec<(u32, ClassKeyState)> {
    keybag
        .class_keys
        .iter()
        .map(|ck| (ck.class, ck.state()))
        .collect()
}

/// Look up the unwrapped class key for a given protection class.
pub(crate) fn get_class_key(keybag: &Keybag, protection_class: u32) -> Result<&[u8]> {
    for ck in &keybag.class_keys {
        if ck.class == protection_class {
            if ck.state() == ClassKeyState::DeviceBound {
                return Err(anyhow!(
                    "Class key {protection_class} is device-bound: it is wrapped under the \
                     device's hardware key as well as the password, and a backup does not \
                     carry that key"
                ));
            }
            if let Some(ref key) = ck.unwrapped_key {
                return Ok(key);
            } else {
                return Err(anyhow!(
                    "Class key {} not unwrapped (may require device key)",
                    protection_class
                ));
            }
        }
    }
    Err(anyhow!(
        "No class key found for protection class {}",
        protection_class
    ))
}

/// Decrypt the Manifest.db file.
///
/// `manifest_key` from Manifest.plist: first 4 bytes = protection class (LE u32),
/// remaining bytes = wrapped file key. The file key is unwrapped with the
/// appropriate class key, then used to AES-256-CBC decrypt the database (zero IV).
pub fn decrypt_manifest_db(
    encrypted_db: &[u8],
    manifest_key: &[u8],
    keybag: &Keybag,
) -> Result<Vec<u8>> {
    if manifest_key.len() < 8 {
        return Err(anyhow!(
            "ManifestKey too short: {} bytes",
            manifest_key.len()
        ));
    }

    // First 4 bytes: protection class (little-endian u32)
    let protection_class = u32::from_le_bytes([
        manifest_key[0],
        manifest_key[1],
        manifest_key[2],
        manifest_key[3],
    ]);

    let wrapped_file_key = &manifest_key[4..];

    // Unwrap the file key using the class key
    let class_key = get_class_key(keybag, protection_class)?;
    let file_key = unwrap_file_key(wrapped_file_key, class_key)?;

    // Decrypt with AES-256-CBC, zero IV
    aes_cbc_decrypt(encrypted_db, &file_key)
}

/// Decrypt a single backup file.
///
/// `file_key` is the raw (already unwrapped from NSKeyedArchiver) per-file key.
/// `protection_class` identifies which class key to use for unwrapping.
///
/// Class 0 is not an iOS protection class; inside an encrypted backup it only
/// ever arises from a class that could not be read being defaulted to zero. This
/// used to return the input unchanged, so the caller received ciphertext from a
/// function named `decrypt_file` and had no way to tell (B8-026). It is now an
/// error: nothing in this module returns undecrypted bytes as plaintext.
pub fn decrypt_file(
    encrypted_data: &[u8],
    file_key: &[u8],
    protection_class: u32,
    keybag: &Keybag,
) -> Result<Vec<u8>> {
    if protection_class == 0 {
        return Err(anyhow!(
            "Protection class 0 is not a valid iOS class: refusing to return the \
             stored bytes as if they were decrypted"
        ));
    }

    let class_key = get_class_key(keybag, protection_class)?;
    let unwrapped_key = unwrap_file_key(file_key, class_key)?;
    aes_cbc_decrypt(encrypted_data, &unwrapped_key)
}

/// Unwrap a per-file key using a class key via RFC 3394 AES Key Wrap.
pub(crate) fn unwrap_file_key(wrapped_key: &[u8], class_key: &[u8]) -> Result<Vec<u8>> {
    if class_key.len() < 32 {
        // Pad class key to 32 bytes if needed (some class keys are shorter)
        let mut padded = [0u8; 32];
        padded[..class_key.len()].copy_from_slice(class_key);
        let kek = KekAes256::from(padded);
        return kek.unwrap_vec(wrapped_key).map_err(|_| {
            anyhow!("Failed to unwrap file key (AES key unwrap integrity check failed)")
        });
    }

    let key_array: [u8; 32] = class_key[..32]
        .try_into()
        .map_err(|_| anyhow!("Class key wrong size"))?;
    let kek = KekAes256::from(key_array);
    kek.unwrap_vec(wrapped_key)
        .map_err(|_| anyhow!("Failed to unwrap file key (AES key unwrap integrity check failed)"))
}

/// Look up the unwrapped class key for streaming decryption.
/// Returns the class key bytes as an owned Vec.
pub fn get_class_key_for_streaming(keybag: &Keybag, protection_class: u32) -> Result<Vec<u8>> {
    get_class_key(keybag, protection_class).map(|k| k.to_vec())
}

/// Unwrap a per-file key for streaming decryption.
/// Returns the unwrapped 32-byte key suitable for `DecryptedFileDataSource`.
pub fn unwrap_file_key_for_streaming(wrapped_key: &[u8], class_key: &[u8]) -> Result<[u8; 32]> {
    let key = unwrap_file_key(wrapped_key, class_key)?;
    if key.len() < 32 {
        return Err(anyhow!("Unwrapped file key too short: {} bytes", key.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key[..32]);
    Ok(arr)
}

/// Threshold for switching from in-memory to streaming decryption.
/// Files smaller than this are decrypted entirely into memory.
pub const STREAMING_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MB

/// A [`DataSource`] that decrypts an AES-256-CBC encrypted file on demand.
///
/// Instead of loading the entire decrypted file into memory, this reads
/// ciphertext blocks from disk and decrypts only the requested range.
/// AES-CBC decryption of block N only requires ciphertext[N-1] as IV,
/// enabling random-access reads without sequential processing.
///
/// Used for large backup files (>10MB) where in-memory decryption would
/// consume excessive memory.
#[derive(Debug)]
pub struct DecryptedFileDataSource {
    /// Encrypted file on disk
    encrypted_path: PathBuf,
    /// AES-256 cipher for single-block ECB decryption
    cipher: Aes256,
    /// Total size of the encrypted file
    encrypted_size: u64,
    /// Size after PKCS#7 padding removal (actual file content)
    decrypted_size: u64,
}

impl DecryptedFileDataSource {
    /// Create a streaming decryption data source.
    ///
    /// `file_key` is the unwrapped 32-byte AES key for this file.
    /// The decrypted size is computed by reading the last block and
    /// inspecting the PKCS#7 padding.
    pub fn new(encrypted_path: PathBuf, file_key: &[u8; 32]) -> Result<Self> {
        let encrypted_size = std::fs::metadata(&encrypted_path)
            .map_err(|e| anyhow!("Cannot stat encrypted file: {}", e))?
            .len();

        if encrypted_size == 0 || encrypted_size % 16 != 0 {
            return Err(anyhow!(
                "Encrypted file size {} is not a valid AES-CBC ciphertext",
                encrypted_size
            ));
        }

        let cipher = <Aes256 as KeyInit>::new(file_key.into());

        // Determine decrypted size by reading and decrypting the last block
        // to inspect PKCS#7 padding. iOS backup files are always PKCS#7 padded,
        // so a final block that does not carry valid padding means the wrong
        // per-file key was used or the ciphertext is corrupt. Fail closed rather
        // than report the full ciphertext length and serve pad/garbage as
        // plaintext.
        let decrypted_size = {
            let mut last_two_blocks = [0u8; 32];
            let file = std::fs::File::open(&encrypted_path)?;
            use std::io::{Read, Seek, SeekFrom};
            let mut file = std::io::BufReader::new(file);

            if encrypted_size >= 32 {
                file.seek(SeekFrom::End(-32))?;
                file.read_exact(&mut last_two_blocks)?;
                // IV for last block = second-to-last ciphertext block
                let iv = &last_two_blocks[..16];
                let mut last_block = last_two_blocks[16..32].to_vec();
                // Decrypt last block: ECB decrypt then XOR with previous ciphertext
                let block = Block::from_mut_slice(&mut last_block);
                cipher.decrypt_block(block);
                for i in 0..16 {
                    last_block[i] ^= iv[i];
                }
                let pad = validate_pkcs7_final_block(&last_block)?;
                encrypted_size - pad
            } else {
                // Single block (16 bytes)
                file.seek(SeekFrom::Start(0))?;
                file.read_exact(&mut last_two_blocks[..16])?;
                let mut last_block = last_two_blocks[..16].to_vec();
                // IV is zero for first (and only) block
                let block = Block::from_mut_slice(&mut last_block);
                cipher.decrypt_block(block);
                let pad = validate_pkcs7_final_block(&last_block)?;
                16 - pad
            }
        };

        Ok(Self {
            encrypted_path,
            cipher,
            encrypted_size,
            decrypted_size,
        })
    }
}

impl DataSource for DecryptedFileDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.decrypted_size || buf.is_empty() {
            return Ok(0);
        }

        // Clamp read to decrypted size
        let available = self.decrypted_size - offset;
        let to_read = std::cmp::min(buf.len() as u64, available) as usize;

        // Calculate which AES blocks we need
        let first_block = (offset / 16) as usize;
        let last_block = ((offset + to_read as u64 - 1) / 16) as usize;
        let num_blocks = last_block - first_block + 1;

        // Read ciphertext: we need the previous block (for IV) plus our blocks
        let ct_start = if first_block > 0 {
            ((first_block - 1) * 16) as u64
        } else {
            0
        };
        let ct_end = ((last_block + 1) * 16) as u64;
        let ct_end = std::cmp::min(ct_end, self.encrypted_size);
        let ct_len = (ct_end - ct_start) as usize;

        let mut ciphertext = vec![0u8; ct_len];
        {
            use std::io::{Read, Seek, SeekFrom};
            let file = std::fs::File::open(&self.encrypted_path)?;
            let mut file = std::io::BufReader::new(file);
            file.seek(SeekFrom::Start(ct_start))?;
            file.read_exact(&mut ciphertext)?;
        }

        // Decrypt blocks using CBC: plaintext[i] = ECB_decrypt(ct[i]) XOR ct[i-1]
        let mut plaintext = Vec::with_capacity(num_blocks * 16);

        for i in 0..num_blocks {
            let block_idx = first_block + i;

            // Get IV: previous ciphertext block, or zero IV for block 0
            let iv: [u8; 16] = if block_idx == 0 {
                [0u8; 16]
            } else if first_block > 0 {
                // Previous block is at offset (block_idx - first_block) * 16 in our buffer
                // But we read from first_block - 1, so the prev block is at
                // (block_idx - 1 - (first_block - 1)) * 16 = (block_idx - first_block) * 16
                let prev_offset = (block_idx - first_block) * 16;
                ciphertext[prev_offset..prev_offset + 16]
                    .try_into()
                    .unwrap()
            } else {
                // first_block == 0, block_idx > 0
                let prev_offset = (block_idx - 1) * 16;
                ciphertext[prev_offset..prev_offset + 16]
                    .try_into()
                    .unwrap()
            };

            // Get the ciphertext block to decrypt
            let ct_offset = if first_block > 0 {
                (block_idx - first_block + 1) * 16
            } else {
                block_idx * 16
            };
            let mut block_data: [u8; 16] =
                ciphertext[ct_offset..ct_offset + 16].try_into().unwrap();

            // ECB decrypt then XOR with IV
            let block = Block::from_mut_slice(&mut block_data);
            self.cipher.decrypt_block(block);
            for j in 0..16 {
                block_data[j] ^= iv[j];
            }

            plaintext.extend_from_slice(&block_data);
        }

        // Copy the requested range from decrypted plaintext
        let start_in_plaintext = (offset % 16) as usize;
        buf[..to_read]
            .copy_from_slice(&plaintext[start_in_plaintext..start_in_plaintext + to_read]);

        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.decrypted_size
    }
}

/// AES-256-CBC decryption with zero IV and PKCS#7 padding removal.
fn aes_cbc_decrypt(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() < 32 {
        return Err(anyhow!("AES-256 key too short: {} bytes", key.len()));
    }
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    if !encrypted.len().is_multiple_of(16) {
        return Err(anyhow!(
            "Encrypted data length {} is not a multiple of 16",
            encrypted.len()
        ));
    }

    let key_bytes: [u8; 32] = key[..32]
        .try_into()
        .map_err(|_| anyhow!("Key conversion failed"))?;
    let iv = [0u8; 16];

    let cipher = Aes256CbcDec::new(&key_bytes.into(), &iv.into());
    let mut buf = encrypted.to_vec();
    cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| anyhow!("AES-256-CBC decryption failed"))?;

    strip_pkcs7_padding(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TLV entry: 4-byte tag (BE) + 4-byte length (BE) + value
    fn tlv(tag: &[u8; 4], value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(tag);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    fn build_test_keybag() -> Vec<u8> {
        let mut kb = Vec::new();
        // UUID
        kb.extend(tlv(b"UUID", &[0xAA; 16]));
        // SALT
        kb.extend(tlv(b"SALT", &[0xBB; 32]));
        // ITER
        kb.extend(tlv(b"ITER", &10000u32.to_be_bytes()));
        // DPSL (iOS 10.2+)
        kb.extend(tlv(b"DPSL", &[0xCC; 20]));
        // DPIC
        kb.extend(tlv(b"DPIC", &1000000u32.to_be_bytes()));
        // Class key 1: class=1, wrap=2 (passcode), wpky=40 bytes
        kb.extend(tlv(b"CLAS", &1u32.to_be_bytes()));
        kb.extend(tlv(b"WRAP", &2u32.to_be_bytes()));
        kb.extend(tlv(b"WPKY", &[0xDD; 40]));
        // Class key 3: class=3, wrap=2, wpky=40 bytes
        kb.extend(tlv(b"CLAS", &3u32.to_be_bytes()));
        kb.extend(tlv(b"WRAP", &2u32.to_be_bytes()));
        kb.extend(tlv(b"WPKY", &[0xEE; 40]));
        kb
    }

    #[test]
    fn test_parse_keybag() {
        let data = build_test_keybag();
        let kb = parse_keybag(&data).unwrap();

        assert_eq!(kb.uuid, vec![0xAA; 16]);
        assert_eq!(kb.salt, vec![0xBB; 32]);
        assert_eq!(kb.iter, 10000);
        assert_eq!(kb.dpsl.as_ref().unwrap(), &vec![0xCC; 20]);
        assert_eq!(kb.dpic, Some(1000000));
        assert_eq!(kb.class_keys.len(), 2);
        assert_eq!(kb.class_keys[0].class, 1);
        assert_eq!(kb.class_keys[0].wrap_type, 2);
        assert_eq!(kb.class_keys[0].wrapped_key, vec![0xDD; 40]);
        assert_eq!(kb.class_keys[1].class, 3);
        assert_eq!(kb.class_keys[1].wrap_type, 2);
        assert_eq!(kb.class_keys[1].wrapped_key, vec![0xEE; 40]);
    }

    #[test]
    fn test_parse_keybag_missing_salt() {
        let mut data = Vec::new();
        data.extend(tlv(b"UUID", &[0xAA; 16]));
        data.extend(tlv(b"ITER", &10000u32.to_be_bytes()));

        let result = parse_keybag(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing SALT"));
    }

    #[test]
    fn test_derive_passcode_key_with_dpsl() {
        // iOS 10.2+ double PBKDF2 path
        let keybag = Keybag {
            uuid: vec![0; 16],
            salt: vec![0x01; 32],
            iter: 1, // low iter for fast test
            dpsl: Some(vec![0x02; 20]),
            dpic: Some(1),
            class_keys: vec![],
        };

        let key = derive_passcode_key("test_password", &keybag).unwrap();
        // Key should be 32 bytes and deterministic
        assert_eq!(key.len(), 32);

        // Same password + params → same key
        let key2 = derive_passcode_key("test_password", &keybag).unwrap();
        assert_eq!(key, key2);

        // Different password → different key
        let key3 = derive_passcode_key("wrong_password", &keybag).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_derive_passcode_key_legacy() {
        // Pre-10.2 single PBKDF2 path (no DPSL/DPIC)
        let keybag = Keybag {
            uuid: vec![0; 16],
            salt: vec![0x01; 32],
            iter: 1,
            dpsl: None,
            dpic: None,
            class_keys: vec![],
        };

        let key = derive_passcode_key("test_password", &keybag).unwrap();
        assert_eq!(key.len(), 32);

        // Verify determinism
        let key2 = derive_passcode_key("test_password", &keybag).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_unwrap_class_key() {
        // Use a known KEK to wrap a key, then unwrap it
        let passcode_key: [u8; 32] = [0x42; 32];
        let plaintext_key: [u8; 32] = [0x99; 32];

        // Wrap the key using aes-kw
        let kek = KekAes256::from(passcode_key);
        let wrapped = kek.wrap_vec(&plaintext_key).unwrap();

        let mut keybag = Keybag {
            uuid: vec![],
            salt: vec![0; 32],
            iter: 1,
            dpsl: None,
            dpic: None,
            class_keys: vec![ClassKey {
                class: 3,
                wrap_type: WRAP_PASSCODE,
                wrapped_key: wrapped,
                unwrapped_key: None,
            }],
        };

        unwrap_class_keys(&mut keybag, &passcode_key).unwrap();
        assert_eq!(
            keybag.class_keys[0].unwrapped_key.as_ref().unwrap(),
            &plaintext_key.to_vec()
        );
    }

    #[test]
    fn test_wrong_password() {
        let correct_key: [u8; 32] = [0x42; 32];
        let wrong_key: [u8; 32] = [0x00; 32];
        let plaintext_key: [u8; 32] = [0x99; 32];

        let kek = KekAes256::from(correct_key);
        let wrapped = kek.wrap_vec(&plaintext_key).unwrap();

        let mut keybag = Keybag {
            uuid: vec![],
            salt: vec![0; 32],
            iter: 1,
            dpsl: None,
            dpic: None,
            class_keys: vec![ClassKey {
                class: 1,
                wrap_type: WRAP_PASSCODE,
                wrapped_key: wrapped,
                unwrapped_key: None,
            }],
        };

        let result = unwrap_class_keys(&mut keybag, &wrong_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Incorrect backup password"));
    }

    #[test]
    fn test_decrypt_file() {
        // Set up a known class key and wrap a file key with it
        let class_key_raw: [u8; 32] = [0x55; 32];
        let file_key_raw: [u8; 32] = [0x77; 32];

        // Wrap the file key
        let class_kek = KekAes256::from(class_key_raw);
        let wrapped_file_key = class_kek.wrap_vec(&file_key_raw).unwrap();

        // Create plaintext and encrypt it
        let mut plaintext = b"Hello, encrypted iOS backup!".to_vec();
        // Pad to 16-byte boundary with PKCS#7
        let pad_len = 16 - (plaintext.len() % 16);
        plaintext.extend(std::iter::repeat_n(pad_len as u8, pad_len));

        // Encrypt with AES-256-CBC, zero IV
        use cbc::cipher::BlockEncryptMut;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let iv = [0u8; 16];
        let cipher = Aes256CbcEnc::new(&file_key_raw.into(), &iv.into());
        let mut ciphertext = plaintext.clone();
        let ct_len = ciphertext.len();
        cipher
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut ciphertext, ct_len)
            .unwrap();

        // Build keybag with the class key already unwrapped
        let keybag = Keybag {
            uuid: vec![],
            salt: vec![0; 32],
            iter: 1,
            dpsl: None,
            dpic: None,
            class_keys: vec![ClassKey {
                class: 3,
                wrap_type: WRAP_PASSCODE,
                wrapped_key: vec![], // not needed since we set unwrapped_key
                unwrapped_key: Some(class_key_raw.to_vec()),
            }],
        };

        let decrypted = decrypt_file(&ciphertext, &wrapped_file_key, 3, &keybag).unwrap();
        assert_eq!(decrypted, b"Hello, encrypted iOS backup!");
    }

    /// B8-026: class 0 is not an iOS protection class — inside an encrypted
    /// backup it only ever means "the class could not be read". Returning the
    /// input unchanged handed ciphertext back from a function named
    /// `decrypt_file`, and the caller attached it as recovered content.
    #[test]
    fn test_decrypt_file_refuses_protection_class_zero() {
        let keybag = Keybag {
            uuid: vec![],
            salt: vec![0; 32],
            iter: 1,
            dpsl: None,
            dpic: None,
            class_keys: vec![],
        };
        let ciphertext = [0xABu8; 32];
        let result = decrypt_file(&ciphertext, &[0u8; 40], 0, &keybag);
        let err = result.expect_err("class 0 must not pass the ciphertext through");
        assert!(
            err.to_string().contains("class 0"),
            "error should name the refusal, got: {err}"
        );
    }

    #[test]
    fn test_strip_pkcs7_padding_valid() {
        // 3 bytes of padding
        let mut data = vec![0x41, 0x42, 0x43, 0x03, 0x03, 0x03];
        strip_pkcs7_padding(&mut data).unwrap();
        assert_eq!(data, vec![0x41, 0x42, 0x43]);

        // Full block of padding (16 bytes)
        let mut data2 = vec![0x10; 16];
        strip_pkcs7_padding(&mut data2).unwrap();
        assert!(data2.is_empty());

        // 1 byte of padding
        let mut data3 = vec![0xAA, 0x01];
        strip_pkcs7_padding(&mut data3).unwrap();
        assert_eq!(data3, vec![0xAA]);
    }

    #[test]
    fn test_strip_pkcs7_padding_invalid() {
        // Empty data
        let mut empty = Vec::new();
        assert!(strip_pkcs7_padding(&mut empty).is_err());

        // Padding byte = 0
        let mut bad1 = vec![0x41, 0x00];
        assert!(strip_pkcs7_padding(&mut bad1).is_err());

        // Inconsistent padding bytes
        let mut bad2 = vec![0x41, 0x02, 0x03];
        assert!(strip_pkcs7_padding(&mut bad2).is_err());

        // Padding byte > 16
        let mut bad3 = vec![0x41, 0x42, 0x11];
        assert!(strip_pkcs7_padding(&mut bad3).is_err());
    }

    #[test]
    fn test_streaming_decryption_roundtrip() {
        // Create known plaintext, encrypt it, write to temp file,
        // then verify DecryptedFileDataSource reads it back correctly
        let file_key: [u8; 32] = [0x77; 32];

        // Multi-block plaintext (80 bytes = 5 blocks, will have PKCS#7 padding)
        let original =
            b"This is a test of streaming decryption for large iOS backup files!!extra bytes";
        assert_eq!(original.len(), 78);

        // Pad to 16-byte boundary
        let pad_len = 16 - (original.len() % 16);
        let mut padded = original.to_vec();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
        assert_eq!(padded.len(), 80); // 5 blocks

        // Encrypt with AES-256-CBC, zero IV
        use cbc::cipher::BlockEncryptMut;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let iv = [0u8; 16];
        let cipher = Aes256CbcEnc::new(&file_key.into(), &iv.into());
        let mut ciphertext = padded.clone();
        let ct_len = ciphertext.len();
        cipher
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut ciphertext, ct_len)
            .unwrap();

        // Write encrypted data to temp file
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &ciphertext).unwrap();

        // Create streaming data source
        let ds = DecryptedFileDataSource::new(tmp.path().to_path_buf(), &file_key).unwrap();

        // Verify size (should be original size, not padded)
        assert_eq!(ds.size(), 78, "Decrypted size should strip PKCS#7 padding");

        // Read entire content
        let mut buf = vec![0u8; 78];
        let n = ds.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 78);
        assert_eq!(&buf, original);

        // Test random access: read from middle of block 2
        let mut mid_buf = vec![0u8; 10];
        let n = ds.read_at(20, &mut mid_buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&mid_buf, &original[20..30]);

        // Test cross-block read (spans blocks 0-1)
        let mut cross_buf = vec![0u8; 20];
        let n = ds.read_at(10, &mut cross_buf).unwrap();
        assert_eq!(n, 20);
        assert_eq!(&cross_buf, &original[10..30]);

        // Test read at end (partial read)
        let mut end_buf = vec![0u8; 20];
        let n = ds.read_at(70, &mut end_buf).unwrap();
        assert_eq!(n, 8); // Only 8 bytes remaining
        assert_eq!(&end_buf[..8], &original[70..78]);

        // Test read past end
        let mut past_buf = vec![0u8; 10];
        let n = ds.read_at(100, &mut past_buf).unwrap();
        assert_eq!(n, 0);
    }

    /// Encrypt `plaintext` (already a 16-byte multiple) with AES-256-CBC, zero
    /// IV, NoPadding, and write the ciphertext to a fresh temp file.
    fn encrypt_to_temp(file_key: &[u8; 32], plaintext: &[u8]) -> tempfile::NamedTempFile {
        use cbc::cipher::BlockEncryptMut;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let cipher = Aes256CbcEnc::new(file_key.into(), &[0u8; 16].into());
        let mut ct = plaintext.to_vec();
        let n = ct.len();
        cipher
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut ct, n)
            .unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &ct).unwrap();
        tmp
    }

    #[test]
    fn test_streaming_new_rejects_bad_padding_single_block() {
        // A 16-byte plaintext whose final byte is 0x00 is invalid PKCS#7. Because
        // we encrypt with the SAME key we hand to `new`, decryption is exact, so
        // the bad pad is deterministic. `new` must fail closed, not report size.
        let file_key: [u8; 32] = [0x21; 32];
        let mut pt = [0xAAu8; 16];
        pt[15] = 0x00; // pad byte 0 -> invalid
        let tmp = encrypt_to_temp(&file_key, &pt);
        let res = DecryptedFileDataSource::new(tmp.path().to_path_buf(), &file_key);
        assert!(res.is_err(), "invalid padding must fail closed, got Ok");
    }

    #[test]
    fn test_streaming_new_rejects_bad_padding_multi_block() {
        // 32-byte plaintext whose final byte is 0x20 (32 > 16): invalid pad.
        let file_key: [u8; 32] = [0x33; 32];
        let mut pt = [0xBBu8; 32];
        pt[31] = 0x20;
        let tmp = encrypt_to_temp(&file_key, &pt);
        let res = DecryptedFileDataSource::new(tmp.path().to_path_buf(), &file_key);
        assert!(res.is_err(), "invalid padding must fail closed, got Ok");
    }

    #[test]
    fn test_streaming_new_rejects_inconsistent_padding() {
        // Final byte claims 3 bytes of padding but the preceding two are not 3.
        let file_key: [u8; 32] = [0x44; 32];
        let mut pt = [0xCCu8; 16];
        pt[13] = 0x01;
        pt[14] = 0x02;
        pt[15] = 0x03; // pad=3 but bytes are 01,02,03 -> inconsistent
        let tmp = encrypt_to_temp(&file_key, &pt);
        let res = DecryptedFileDataSource::new(tmp.path().to_path_buf(), &file_key);
        assert!(
            res.is_err(),
            "inconsistent padding must fail closed, got Ok"
        );
    }

    #[test]
    fn test_streaming_decryption_single_block() {
        // Test with data that fits in exactly one block after padding
        let file_key: [u8; 32] = [0x88; 32];
        let original = b"Short";
        let pad_len = 16 - original.len() % 16;
        let mut padded = original.to_vec();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));

        use cbc::cipher::BlockEncryptMut;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let cipher = Aes256CbcEnc::new(&file_key.into(), &[0u8; 16].into());
        let mut ciphertext = padded.clone();
        let ct_len = ciphertext.len();
        cipher
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut ciphertext, ct_len)
            .unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &ciphertext).unwrap();

        let ds = DecryptedFileDataSource::new(tmp.path().to_path_buf(), &file_key).unwrap();
        assert_eq!(ds.size(), 5);

        let mut buf = vec![0u8; 5];
        let n = ds.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, original);
    }

    /// Wrap `key` under `kek` (RFC 3394) — the fixture side of a keybag entry.
    fn wrap_under(kek: [u8; 32], key: &[u8; 32]) -> Vec<u8> {
        KekAes256::from(kek).wrap_vec(key).unwrap()
    }

    /// A keybag with class 7 passcode-wrapped (WRAP=2) and class 9
    /// passcode- and device-wrapped (WRAP=3). The semantics were pinned on
    /// the Hickman iOS 17 backup: its five WRAP=3 classes pass the passcode
    /// layer's RFC 3394 check, yet the value that yields opens no item key
    /// (696 genp, 5 cert, 14 keys all fail) — it is not the class key.
    fn keybag_with_device_bound_class(passcode_key: [u8; 32]) -> Keybag {
        let entry = |class: u32, wrap_type: u32, key: [u8; 32]| ClassKey {
            class,
            wrap_type,
            wrapped_key: wrap_under(passcode_key, &key),
            unwrapped_key: None,
        };
        Keybag {
            uuid: vec![],
            salt: vec![0; 32],
            iter: 1,
            dpsl: None,
            dpic: None,
            class_keys: vec![
                entry(7, WRAP_PASSCODE, [0x77; 32]),
                entry(9, WRAP_PASSCODE | WRAP_DEVICE, [0x99; 32]),
            ],
        }
    }

    #[test]
    fn device_bound_class_key_is_not_usable() {
        let passcode_key = [0x42; 32];
        let mut kb = keybag_with_device_bound_class(passcode_key);
        // Both passcode layers check out, so the password was tested twice.
        assert_eq!(unwrap_class_keys(&mut kb, &passcode_key).unwrap(), 2);

        assert_eq!(usable_class_key(&kb, 7).unwrap(), &[0x77; 32]);
        let err = usable_class_key(&kb, 9).unwrap_err().to_string();
        assert!(err.contains("device-bound"), "{err}");
        assert!(get_class_key(&kb, 9).is_err());

        assert_eq!(kb.class_keys[0].state(), ClassKeyState::Usable);
        assert_eq!(kb.class_keys[1].state(), ClassKeyState::DeviceBound);
        // The passcode-layer value of a device-bound class is not kept.
        assert!(kb.class_keys[1].unwrapped_key.is_none());
    }

    #[test]
    fn keybag_debug_never_prints_key_bytes() {
        let passcode_key = [0x42; 32];
        let mut kb = keybag_with_device_bound_class(passcode_key);
        unwrap_class_keys(&mut kb, &passcode_key).unwrap();
        let text = format!("{kb:?}");
        for needle in [
            hex::encode([0x77u8; 32]),
            "119, 119, 119".to_string(), // 0x77 as a decimal byte run
            hex::encode([0x42u8; 32]),
            "66, 66, 66".to_string(),
        ] {
            assert!(!text.contains(&needle), "{needle} in {text}");
        }
        assert!(text.contains("<redacted>"));
        assert!(
            text.contains("DeviceBound") || text.contains("device_bound"),
            "{text}"
        );
    }
}
