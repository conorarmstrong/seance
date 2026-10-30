#![forbid(unsafe_code)]
//! LUKS (Linux Unified Key Setup) volume decryption for Séance.
//!
//! Encrypted LUKS volumes were previously only *detected*. This crate turns an
//! encrypted LUKS1 or LUKS2 volume plus a passphrase into a plaintext
//! [`DataSource`](seance_core::data_source::DataSource) the rest of the pipeline
//! (partition/filesystem parsers, carvers, hashers) can read transparently.
//!
//! # Flow
//!
//! 1. [`is_luks`] cheaply checks the LUKS magic.
//! 2. [`unlock_luks`] parses the header, and for each active keyslot derives the
//!    keyslot key from the passphrase (PBKDF2 for LUKS1; PBKDF2 or Argon2 for
//!    LUKS2), decrypts the keyslot's anti-forensic material, AF-merges it to a
//!    candidate master key, and verifies that candidate against the stored
//!    digest. On success it returns a [`LuksDecryptingDataSource`].
//!
//! Only the AES-XTS cipher family (the LUKS default, `aes-xts-plain64`) is
//! supported; other ciphers return [`LuksError::Unsupported`].

mod af;
mod error;
mod hash;
mod header;
pub mod module;
mod source;
mod xts;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use seance_core::data_source::DataSource;
use std::sync::Arc;

pub use error::LuksError;
pub use header::{has_luks_magic, Luks1Header, Luks2Header, LuksHeader};
pub use module::LuksDecryptor;
pub use source::LuksDecryptingDataSource;

use hash::HashSpec;
use header::SECTOR;

/// Returns `true` if `volume` begins with the LUKS magic bytes.
pub fn is_luks(volume: &dyn DataSource) -> bool {
    has_luks_magic(volume)
}

/// Unlock a LUKS volume with a passphrase, returning a decrypting data source.
///
/// Tries every active keyslot; succeeds on the first that verifies. Returns
/// [`LuksError::BadPassphrase`] if none match, or [`LuksError::Unsupported`] for
/// ciphers/KDFs this implementation does not handle.
pub fn unlock_luks(
    volume: Arc<dyn DataSource>,
    passphrase: &str,
) -> Result<Arc<dyn DataSource>, LuksError> {
    match header::parse(volume.as_ref())? {
        LuksHeader::V1(hdr) => {
            let src = unlock_luks1(&volume, &hdr, passphrase)?;
            Ok(Arc::new(src))
        }
        LuksHeader::V2(hdr) => {
            let src = unlock_luks2(&volume, &hdr, passphrase)?;
            Ok(Arc::new(src))
        }
    }
}

/// Ceil-divide `n` up to a multiple of `SECTOR`.
fn round_up_sector(n: u64) -> u64 {
    n.div_ceil(SECTOR) * SECTOR
}

/// Read `len` bytes at `offset`, zero-padding a short read at end-of-device.
fn read_padded(vol: &dyn DataSource, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let n = vol.read_at(offset + filled as u64, &mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(buf)
}

/// LUKS fixes the anti-forensic stripe count at 4000; a master key never
/// exceeds a few hundred bytes. These caps bound attacker-controlled keyslot
/// geometry (LUKS1 keyslot header / LUKS2 JSON) so `key_size * stripes` cannot
/// overflow or drive a multi-terabyte allocation (an OOM abort escapes
/// catch_unwind).
const MAX_STRIPES: usize = 4000;
const MAX_KEY_BYTES: usize = 1024;

/// Validate keyslot AF geometry and return the anti-forensic material length in
/// bytes. Rejects zero/oversized key sizes and stripe counts, and guards the
/// multiply against overflow.
fn validated_af_len(key_size: usize, stripes: usize) -> Result<usize, LuksError> {
    if !(1..=MAX_KEY_BYTES).contains(&key_size) || !(1..=MAX_STRIPES).contains(&stripes) {
        return Err(LuksError::Unsupported(format!(
            "implausible keyslot geometry: key_size={key_size}, stripes={stripes}"
        )));
    }
    key_size
        .checked_mul(stripes)
        .ok_or_else(|| LuksError::Unsupported("keyslot AF length overflow".into()))
}

/// Accept only AES-XTS ciphers (the LUKS default). `spec` is the full cipher
/// string, e.g. "aes-xts-plain64".
fn ensure_aes_xts(spec: &str) -> Result<(), LuksError> {
    let lower = spec.to_ascii_lowercase();
    if lower.starts_with("aes") && lower.contains("xts") {
        Ok(())
    } else {
        Err(LuksError::Unsupported(format!("cipher '{spec}'")))
    }
}

// ---------------------------------------------------------------------------
// LUKS1
// ---------------------------------------------------------------------------

fn unlock_luks1(
    volume: &Arc<dyn DataSource>,
    hdr: &Luks1Header,
    passphrase: &str,
) -> Result<LuksDecryptingDataSource, LuksError> {
    ensure_aes_xts(&format!("{}-{}", hdr.cipher_name, hdr.cipher_mode))?;
    let hash = HashSpec::parse(&hdr.hash_spec)?;
    let key_bytes = hdr.key_bytes as usize;
    // Bound key_bytes before it sizes the slot_key allocation below.
    if !(1..=MAX_KEY_BYTES).contains(&key_bytes) {
        return Err(LuksError::Unsupported(format!(
            "implausible key_bytes {key_bytes}"
        )));
    }

    for slot in hdr.keyslots.iter().filter(|s| s.active) {
        let stripes = slot.stripes as usize;
        // Validate geometry (rejects stripes == 0 and out-of-range values) before
        // any allocation sized from it.
        let af_len = match validated_af_len(key_bytes, stripes) {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Passphrase -> keyslot key via PBKDF2.
        let mut slot_key = vec![0u8; key_bytes];
        hash.pbkdf2(
            passphrase.as_bytes(),
            &slot.salt,
            slot.iterations,
            &mut slot_key,
        );

        // Decrypt the anti-forensic key material with the keyslot key.
        let read_len = round_up_sector(af_len as u64) as usize;
        let km_off = slot.key_material_offset_sectors as u64 * SECTOR;
        let mut material = read_padded(volume.as_ref(), km_off, read_len)?;
        xts::decrypt_sectors(&slot_key, SECTOR as usize, 0, &mut material)?;

        // Recover and verify the candidate master key.
        let candidate = af::af_merge(&material[..af_len], key_bytes, stripes, hash);
        if verify_luks1_mk(hdr, hash, &candidate) {
            let payload_offset = hdr.payload_offset_sectors as u64 * SECTOR;
            return Ok(LuksDecryptingDataSource::new(
                Arc::clone(volume),
                candidate,
                payload_offset,
                SECTOR as usize,
                0,
            ));
        }
    }
    Err(LuksError::BadPassphrase)
}

fn verify_luks1_mk(hdr: &Luks1Header, hash: HashSpec, candidate: &[u8]) -> bool {
    let mut check = [0u8; header::LUKS1_DIGEST_SIZE];
    hash.pbkdf2(
        candidate,
        &hdr.mk_digest_salt,
        hdr.mk_digest_iterations,
        &mut check,
    );
    check == hdr.mk_digest
}

// ---------------------------------------------------------------------------
// LUKS2
// ---------------------------------------------------------------------------

fn unlock_luks2(
    volume: &Arc<dyn DataSource>,
    hdr: &Luks2Header,
    passphrase: &str,
) -> Result<LuksDecryptingDataSource, LuksError> {
    let meta = &hdr.meta;

    // The active data segment describes how the payload is encrypted.
    let seg = meta
        .segments
        .values()
        .find(|s| s.kind == "crypt")
        .ok_or_else(|| LuksError::Unsupported("no crypt segment".into()))?;
    let seg_enc = seg
        .encryption
        .as_deref()
        .ok_or_else(|| LuksError::Metadata("segment missing encryption".into()))?;
    ensure_aes_xts(seg_enc)?;
    let sector_size = seg.sector_size.unwrap_or(512);
    // sector_size (attacker JSON) drives divisions and buffer sizing in the
    // decrypting source; 0 would divide-by-zero panic and huge values would
    // allocate multi-TB buffers. Accept only the LUKS-valid sizes.
    if !matches!(sector_size, 512 | 1024 | 2048 | 4096) {
        return Err(LuksError::Metadata(format!(
            "invalid segment sector_size {sector_size}"
        )));
    }
    let payload_offset: u64 = seg
        .offset
        .parse()
        .map_err(|_| LuksError::Metadata(format!("bad segment offset '{}'", seg.offset)))?;
    let iv_offset: u128 = seg
        .iv_tweak
        .as_deref()
        .unwrap_or("0")
        .parse()
        .map_err(|_| LuksError::Metadata("bad segment iv_tweak".into()))?;

    for (slot_id, ks) in meta.keyslots.iter().filter(|(_, k)| k.kind == "luks2") {
        if ks.area.kind != "raw" {
            continue;
        }
        if ensure_aes_xts(&ks.area.encryption).is_err() {
            continue;
        }
        // ks.area.key_size sizes the derive_kdf output allocation; bound it too.
        if !(1..=MAX_KEY_BYTES).contains(&ks.area.key_size) {
            continue;
        }
        // Validate AF geometry (rejects stripes == 0 and oversized/overflowing
        // key_size * stripes) before any allocation sized from it.
        let af_len = match validated_af_len(ks.key_size, ks.af.stripes) {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Passphrase -> keyslot area key via the slot's KDF.
        let area_key = match derive_kdf(&ks.kdf, passphrase, ks.area.key_size) {
            Ok(k) => k,
            Err(_) => continue,
        };

        // Decrypt the keyslot's anti-forensic material.
        let read_len = round_up_sector(af_len as u64) as usize;
        let area_off: u64 =
            ks.area.offset.parse().map_err(|_| {
                LuksError::Metadata(format!("bad area offset '{}'", ks.area.offset))
            })?;
        let mut material = read_padded(volume.as_ref(), area_off, read_len)?;
        xts::decrypt_sectors(&area_key, SECTOR as usize, 0, &mut material)?;

        let af_hash = HashSpec::parse(&ks.af.hash)?;
        let candidate = af::af_merge(&material[..af_len], ks.key_size, ks.af.stripes, af_hash);

        // Verify the candidate against any digest that covers this keyslot.
        for dig in meta
            .digests
            .values()
            .filter(|d| d.keyslots.iter().any(|k| k == slot_id))
        {
            if verify_luks2_digest(dig, &candidate)? {
                return Ok(LuksDecryptingDataSource::new(
                    Arc::clone(volume),
                    candidate,
                    payload_offset,
                    sector_size,
                    iv_offset,
                ));
            }
        }
    }
    Err(LuksError::BadPassphrase)
}

fn verify_luks2_digest(dig: &header::Luks2Digest, candidate: &[u8]) -> Result<bool, LuksError> {
    if dig.kind != "pbkdf2" {
        return Err(LuksError::Unsupported(format!(
            "digest type '{}'",
            dig.kind
        )));
    }
    let hash = HashSpec::parse(&dig.hash)?;
    let salt = B64
        .decode(dig.salt.trim())
        .map_err(|e| LuksError::Metadata(format!("bad digest salt: {e}")))?;
    let want = B64
        .decode(dig.digest.trim())
        .map_err(|e| LuksError::Metadata(format!("bad digest value: {e}")))?;
    // An empty stored digest would make `check == want` trivially true for ANY
    // candidate master key (both sides zero-length) — a full verification bypass
    // that would "unlock" a volume with a garbage key. Reject it.
    if want.is_empty() {
        return Err(LuksError::Metadata("empty master-key digest".into()));
    }
    let mut check = vec![0u8; want.len()];
    hash.pbkdf2(candidate, &salt, dig.iterations, &mut check);
    Ok(check == want)
}

/// Derive a key of `out_len` bytes from `passphrase` using a LUKS2 KDF spec.
fn derive_kdf(
    kdf: &header::Luks2Kdf,
    passphrase: &str,
    out_len: usize,
) -> Result<Vec<u8>, LuksError> {
    let salt = B64
        .decode(kdf.salt.trim())
        .map_err(|e| LuksError::Metadata(format!("bad kdf salt: {e}")))?;
    let mut out = vec![0u8; out_len];

    match kdf.kind.as_str() {
        "pbkdf2" => {
            let hash = HashSpec::parse(
                kdf.hash
                    .as_deref()
                    .ok_or_else(|| LuksError::Metadata("pbkdf2 kdf missing hash".into()))?,
            )?;
            let iters = kdf
                .iterations
                .ok_or_else(|| LuksError::Metadata("pbkdf2 kdf missing iterations".into()))?;
            hash.pbkdf2(passphrase.as_bytes(), &salt, iters, &mut out);
        }
        "argon2i" | "argon2id" => {
            let algo = if kdf.kind == "argon2id" {
                Algorithm::Argon2id
            } else {
                Algorithm::Argon2i
            };
            let m = kdf
                .memory
                .ok_or_else(|| LuksError::Metadata("argon2 kdf missing memory".into()))?;
            let t = kdf
                .time
                .ok_or_else(|| LuksError::Metadata("argon2 kdf missing time".into()))?;
            let p = kdf
                .cpus
                .ok_or_else(|| LuksError::Metadata("argon2 kdf missing cpus".into()))?;
            let params = Params::new(m, t, p, Some(out_len))
                .map_err(|e| LuksError::Unsupported(format!("argon2 params: {e}")))?;
            let a = Argon2::new(algo, Version::V0x13, params);
            a.hash_password_into(passphrase.as_bytes(), &salt, &mut out)
                .map_err(|e| LuksError::Unsupported(format!("argon2: {e}")))?;
        }
        other => return Err(LuksError::Unsupported(format!("kdf type '{other}'"))),
    }
    Ok(out)
}

// Test helpers for building synthetic LUKS volumes are exposed within the crate
// so the integration test in `tests/` can construct real crypto round-trips.
#[doc(hidden)]
pub mod test_support {
    pub use crate::af::{af_merge, af_split};
    pub use crate::hash::HashSpec;
    pub use crate::header::{LUKS1_KEY_ENABLED, LUKS_MAGIC, SECTOR};
    pub use crate::xts::{decrypt_sectors, encrypt_sectors};
}

#[cfg(test)]
mod bounds_tests {
    use super::*;

    /// Regression (H2/H3): attacker-controlled keyslot geometry must be bounded
    /// so `key_size * stripes` cannot overflow or drive a huge allocation.
    #[test]
    fn validated_af_len_bounds_geometry() {
        assert_eq!(validated_af_len(64, 4000).unwrap(), 256_000); // LUKS standard
        assert!(validated_af_len(0, 4000).is_err()); // zero key size
        assert!(validated_af_len(64, 0).is_err()); // zero stripes
        assert!(validated_af_len(64, 4001).is_err()); // too many stripes
        assert!(validated_af_len(MAX_KEY_BYTES + 1, 4000).is_err()); // oversized key
        assert!(validated_af_len(usize::MAX, 4000).is_err()); // overflow guard
    }

    /// Regression (M4): an empty stored master-key digest must be rejected rather
    /// than trivially matching any candidate key (a full verification bypass that
    /// would "unlock" a volume with a garbage master key).
    #[test]
    fn empty_digest_is_rejected_not_bypass() {
        let dig = header::Luks2Digest {
            kind: "pbkdf2".into(),
            keyslots: vec!["0".into()],
            segments: vec![],
            hash: "sha256".into(),
            iterations: 1000,
            salt: B64.encode([0u8; 32]),
            digest: String::new(), // empty -> decodes to []
        };
        let res = verify_luks2_digest(&dig, b"any garbage candidate key");
        assert!(
            res.is_err(),
            "empty digest must be rejected, not accepted as a match"
        );
    }
}
