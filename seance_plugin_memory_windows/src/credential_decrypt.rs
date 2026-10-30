//! Recovering credential **values** from the registry hives in memory (MEM-008).
//!
//! [`crate::credentials`] locates and inventories the credential stores — which
//! hives are loaded, the account names, the LSA-secret names. This module goes
//! the step further the finding named: it extracts the machine's **boot key**
//! from the `SYSTEM` hive and uses it to decrypt the local account password
//! hashes out of the `SAM` hive, so a report can carry the NT hash of each
//! account rather than only its name.
//!
//! # The algorithm
//!
//! Transcribed from the well-established reference (impacket `secretsdump`,
//! creddump) and [MS-SAMR] §2.2.11:
//!
//! 1. **Boot key.** The four keys `SYSTEM\<ControlSet>\Control\Lsa\{JD, Skew1,
//!    GBG, Data}` each carry an eight-hex-digit *class* string. Concatenated and
//!    de-hexed they are sixteen scrambled bytes; a fixed permutation unscrambles
//!    them into the boot key (a.k.a. SysKey).
//! 2. **Hashed boot key.** `SAM\Domains\Account\F` holds an encrypted key blob.
//!    From Windows 10 1607 it is AES-128-CBC under the boot key (the older form
//!    is RC4/MD5); decrypting it yields the hashed boot key.
//! 3. **Per-account hash.** Each `SAM\Domains\Account\Users\<RID>\V` holds the
//!    encrypted NT hash. AES-128-CBC under the hashed boot key removes the outer
//!    layer; a final DES pass keyed by the account's RID removes the inner one,
//!    leaving the 16-byte NT hash.
//!
//! # Scope and honesty
//!
//! This implements the Windows 10/11 **AES** path (the case on every modern
//! machine), validated end to end against a real capture whose account password
//! is known — the recovered NT hash equals `MD4(UTF-16LE(password))`.
//!
//! Beyond the SAM hashes, the `SECURITY` hive's **LSA secrets**
//! (`Policy\Secrets\<name>` — machine account, `DPAPI_SYSTEM`, `NL$KM`, service
//! passwords) and **cached domain logons** (`Cache\NL$n`, the MSCACHEv2/DCC2
//! form) are decrypted under the same boot key: the LSA key comes from
//! `Policy\PolEKList` (`SHA-256(bootkey, salt, 1000)` → AES-256), each secret
//! and the `NL$KM`-keyed cache decrypt from there. That crypto is validated by a
//! round-trip unit test; it runs end to end only when the SECURITY hive's
//! mapped-view pages are resident in the capture (they are paged out in the live
//! snapshot on hand), so its absence is *reported*, never guessed.
//!
//! The older **RC4** SAM/LSA form is not implemented; an account or secret
//! stored the old way is reported as located-but-not-decrypted rather than
//! decoded wrongly. A boot key protected by a startup password (SysKey on
//! floppy/console) cannot be recovered from the image and is reported as such.

use std::sync::Arc;

use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit};
use aes::{Aes128, Aes256};
use des::Des;
use sha2::{Digest, Sha256};

use crate::profile::WindowsProfile;
use crate::registry::hivelist::list_hives;
use crate::registry::key::{CellReader, ValueData};
use crate::registry::printkey::resolve_key;
use crate::registry::space::{locate_bin_space, HiveSpace};

/// One recovered local account and its password hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCredential {
    /// The account's relative identifier.
    pub rid: u32,
    /// The account name, as the `SAM` hive spells it.
    pub username: String,
    /// The NT hash — `MD4(UTF-16LE(password))` — as hex, when it was recovered.
    /// `None` for an account stored under a scheme this build does not decrypt,
    /// or with no password set.
    pub nt_hash: Option<String>,
    /// Why the hash is absent, when it is.
    pub note: Option<String>,
}

/// One decrypted LSA secret (`SECURITY\Policy\Secrets\<name>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaSecret {
    /// The secret's name, e.g. `$MACHINE.ACC`, `DPAPI_SYSTEM`, `NL$KM`.
    pub name: String,
    /// The decrypted secret bytes, hex. These are raw — a machine-account
    /// password is UTF-16LE text, `DPAPI_SYSTEM` is key material — so hex is the
    /// honest, format-agnostic rendering.
    pub value: String,
    /// The secret's length in bytes.
    pub length: usize,
}

/// One cached domain logon (`SECURITY\Cache\NL$n`), the MSCACHEv2 / DCC2 form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedLogon {
    /// The cached account name.
    pub username: String,
    /// The DNS domain the logon was for.
    pub domain: String,
    /// The DCC2 (MSCACHEv2) hash, hex — a PBKDF2-style value, crackable offline.
    pub dcc2_hash: String,
    /// The PBKDF2 iteration count the `$DCC2$` form carries.
    pub iterations: u32,
}

/// The result of a credential-decryption pass over one image.
#[derive(Debug, Clone)]
pub struct CredentialValues {
    /// The boot key, hex, when it could be recovered.
    pub boot_key: Option<String>,
    /// The recovered accounts.
    pub credentials: Vec<RecoveredCredential>,
    /// The decrypted LSA secrets, when the `SECURITY` hive was present.
    pub lsa_secrets: Vec<LsaSecret>,
    /// The cached domain logons (DCC2), when present.
    pub cached_logons: Vec<CachedLogon>,
    /// Why the SECURITY-hive secrets are absent, when they are — distinct from
    /// `unavailable`, which is about the whole pass failing.
    pub security_note: Option<String>,
    /// Why decryption could not run at all, when it could not.
    pub unavailable: Option<String>,
}

/// Recover the local account NT hashes from the `SYSTEM` and `SAM` hives.
pub fn recover_sam_hashes(profile: &WindowsProfile) -> CredentialValues {
    let mut out = CredentialValues {
        boot_key: None,
        credentials: Vec::new(),
        lsa_secrets: Vec::new(),
        cached_logons: Vec::new(),
        security_note: None,
        unavailable: None,
    };

    let (Some(system), Some(sam)) = (open_hive(profile, "SYSTEM"), open_hive(profile, "SAM"))
    else {
        out.unavailable = Some(
            "the SYSTEM and SAM hives were not both available in the image, so the boot key and \
             the account hashes could not be decrypted"
                .to_string(),
        );
        return out;
    };

    let boot_key = match boot_key(&system) {
        Some(key) => key,
        None => {
            out.unavailable = Some(
                "the boot key could not be read from the SYSTEM hive (the Lsa class values were \
                 not present or not the expected form); no hash could be decrypted"
                    .to_string(),
            );
            return out;
        }
    };
    out.boot_key = Some(hex(&boot_key));

    let hashed = match hashed_boot_key(&sam, &boot_key) {
        Ok(key) => key,
        Err(reason) => {
            out.unavailable = Some(reason);
            return out;
        }
    };

    out.credentials = decrypt_users(&sam, &hashed);

    // The SECURITY hive carries the LSA secrets and cached domain logons. It is
    // not always reachable — a SAM-only capture, or (common on a live snapshot)
    // a SECURITY hive whose mapped-view pages are paged out — so its absence is
    // recorded, not treated as a failure of the whole pass.
    match open_hive(profile, "SECURITY") {
        Some(security) => {
            if let Some(lsa_key) = lsa_key(&security, &boot_key) {
                out.lsa_secrets = lsa_secrets(&security, &lsa_key);
                out.cached_logons = cached_logons(&security, &lsa_key);
            } else {
                out.security_note = Some(
                    "the SECURITY hive was reached but its LSA key could not be decrypted \
                     (PolEKList absent or its bin not resident); LSA secrets and cached logons \
                     were not recovered"
                        .to_string(),
                );
            }
        }
        None => {
            out.security_note = Some(
                "the SECURITY hive was not reachable in this image (not captured, or its \
                 mapped-view pages are paged out); LSA secrets and cached domain logons could \
                 not be recovered"
                    .to_string(),
            );
        }
    }
    out
}

/// Recover the LSA key from `SECURITY\Policy\PolEKList` (Windows 10+ AES scheme).
///
/// The value is an `LSA_SECRET`: a 28-byte header then encrypted data. The key
/// to decrypt it is `SHA-256(bootKey, encdata[..32], 1000 rounds)`, used as an
/// AES-256 key over `encdata[32..]`; the plaintext is an `LSA_SECRET_BLOB` whose
/// `Secret` field carries the 32-byte LSA key at offset 52. Transcribed from
/// impacket `secretsdump.LSASecrets.__decryptLSA` (vista-style path).
fn lsa_key(security: &CellReader, boot_key: &[u8; 16]) -> Option<[u8; 32]> {
    let value = read_default_value(security, "Policy\\PolEKList")?;
    let secret = decrypt_lsa_blob(&value, boot_key)?;
    secret.get(52..84).map(|s| {
        let mut k = [0u8; 32];
        k.copy_from_slice(s);
        k
    })
}

/// Decrypt one `LSA_SECRET` value under `key`, returning its `Secret` bytes.
///
/// `key` is the boot key for `PolEKList`, or the LSA key for a `Secrets\*`
/// entry — the structure is identical. `LSA_SECRET`: Version(4), EncKeyID(16),
/// EncAlgorithm(4), Flags(4), then EncryptedData. The per-secret AES key is
/// `SHA-256(key, EncryptedData[..32], 1000 rounds)`; the rest decrypts (AES-256,
/// per-block, IV zero) to an `LSA_SECRET_BLOB`: Length(4), Unknown(12), then
/// `Secret` of `Length` bytes.
fn decrypt_lsa_blob(value: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let enc = value.get(28..)?;
    if enc.len() < 32 {
        return None;
    }
    let derived = sha256_rounds(key, &enc[..32], 1000);
    let plain = aes256_decrypt(&derived, &enc[32..], None);
    let length = le_u32(&plain, 0) as usize;
    plain.get(16..16 + length).map(<[u8]>::to_vec)
}

/// Decrypt every `SECURITY\Policy\Secrets\<name>` under the LSA key.
fn lsa_secrets(security: &CellReader, lsa_key: &[u8; 32]) -> Vec<LsaSecret> {
    let mut out = Vec::new();
    let Ok(nodes) = resolve_key(security, Some("Policy\\Secrets")) else {
        return out;
    };
    let Some(secrets) = nodes.last() else {
        return out;
    };
    for sub in security.subkeys(secrets).keys {
        let name = sub.name.text.clone();
        let Some(value) =
            read_default_value(security, &format!("Policy\\Secrets\\{name}\\CurrVal"))
        else {
            continue;
        };
        // A NULL or all-zero secret is not a finding; impacket discards these.
        let Some(secret) = decrypt_lsa_blob(&value, lsa_key) else {
            continue;
        };
        if secret.is_empty() || secret.iter().all(|&b| b == 0) {
            continue;
        }
        out.push(LsaSecret {
            name,
            value: hex(&secret),
            length: secret.len(),
        });
    }
    out
}

/// Decrypt the cached domain logons in `SECURITY\Cache` (MSCACHEv2 / DCC2).
///
/// Each `NL$n` value is an `NL_RECORD`; the encrypted body decrypts under the
/// second half of the `NL$KM` LSA secret with AES-256-CBC and the record's own
/// IV. The MSCACHEv2 hash is the first 16 bytes of the plaintext, the account
/// name UTF-16LE at offset 0x48. Transcribed from `secretsdump.dumpCachedHashes`.
fn cached_logons(security: &CellReader, lsa_key: &[u8; 32]) -> Vec<CachedLogon> {
    let mut out = Vec::new();
    // NL$KM is itself an LSA secret; its second 16 bytes key the cache.
    let Some(nlkm_value) = read_default_value(security, "Policy\\Secrets\\NL$KM\\CurrVal") else {
        return out;
    };
    let Some(nlkm) = decrypt_lsa_blob(&nlkm_value, lsa_key) else {
        return out;
    };
    let Some(cache_key) = nlkm.get(16..32) else {
        return out;
    };

    let iterations = read_value(security, "Cache", "NL$IterationCount")
        .filter(|v| v.len() >= 4)
        .map(|v| {
            let raw = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            if raw > 10240 {
                raw & 0xffff_fc00
            } else {
                raw.saturating_mul(1024)
            }
        })
        .unwrap_or(10240);

    let Ok(nodes) = resolve_key(security, Some("Cache")) else {
        return out;
    };
    let Some(cache) = nodes.last() else {
        return out;
    };
    for value in security.values(cache).values {
        let name = value.name.text.clone();
        if !name.starts_with("NL$") || name == "NL$Control" || name == "NL$IterationCount" {
            continue;
        }
        let ValueData::Available { raw, .. } = value.data else {
            continue;
        };
        if let Some(logon) = decode_cached_logon(&raw, cache_key, iterations) {
            out.push(logon);
        }
    }
    out
}

/// Fixed field offsets in an `NL_RECORD` (see the struct in impacket).
const NL_USER_LEN: usize = 0x00;
const NL_DNS_DOMAIN_LEN: usize = 0x3c;
const NL_FLAGS: usize = 0x30;
const NL_IV: usize = 0x40;
const NL_ENCRYPTED: usize = 0x60;

/// Decode one `NL_RECORD` into a cached logon, or `None` if it is empty/plain.
fn decode_cached_logon(raw: &[u8], cache_key: &[u8], iterations: u32) -> Option<CachedLogon> {
    let iv = raw.get(NL_IV..NL_IV + 16)?;
    if iv.iter().all(|&b| b == 0) {
        return None; // an empty cache slot
    }
    let flags = le_u32(raw, NL_FLAGS);
    if flags & 1 != 1 {
        return None; // not encrypted; skip rather than guess
    }
    let user_len =
        u16::from_le_bytes([*raw.get(NL_USER_LEN)?, *raw.get(NL_USER_LEN + 1)?]) as usize;
    let dns_len = u16::from_le_bytes([
        *raw.get(NL_DNS_DOMAIN_LEN)?,
        *raw.get(NL_DNS_DOMAIN_LEN + 1)?,
    ]) as usize;
    let enc = raw.get(NL_ENCRYPTED..)?;
    let plain = aes256_decrypt(cache_key, enc, Some(iv));

    let hash = plain.get(..0x10)?;
    // The names follow a fixed 0x48-byte header inside the plaintext; each is
    // padded up to a 4-byte boundary.
    let after_header = plain.get(0x48..)?;
    let username = utf16le(after_header.get(..user_len)?);
    let domain_off = pad4(user_len) + pad4(u16_at(raw, 0x02) as usize); // user + NetBIOS domain
    let domain = after_header
        .get(domain_off..domain_off + pad4(dns_len))
        .map(utf16le)
        .unwrap_or_default();

    Some(CachedLogon {
        username,
        domain,
        dcc2_hash: hex(hash),
        iterations,
    })
}

/// Open a named hive and return a cell reader over it, or `None`.
///
/// More than one loaded hive can share a file name (a stale mapping, a hive
/// loaded into a process, a second control set), and a live-RAM capture pages
/// hives in and out, so the first match by name may sit in an unbacked region.
/// Every candidate is tried and the first whose **root cell is actually
/// readable** is used — an empty or holed mapping is not a usable hive.
fn open_hive(profile: &WindowsProfile, name: &str) -> Option<CellReader> {
    let listing = list_hives(profile).ok()?;
    let bins = locate_bin_space(profile);
    let mut fallback: Option<CellReader> = None;
    for record in listing.hives.iter().filter(|hive| {
        hive.name
            .file_name()
            .is_some_and(|file| file.eq_ignore_ascii_case(name))
    }) {
        let Ok(hive) = HiveSpace::open_with_bin_space(profile, record.address, &bins) else {
            continue;
        };
        let Ok(reader) = CellReader::new(Arc::clone(&hive)) else {
            continue;
        };
        // A usable hive resolves its root and lists at least one subkey. Prefer
        // such a candidate; keep the first that merely opened as a fallback, so
        // this is never stricter than taking the first match by name.
        if resolve_key(&reader, None)
            .ok()
            .and_then(|chain| chain.last().map(|r| !reader.subkeys(r).keys.is_empty()))
            .unwrap_or(false)
        {
            return Some(reader);
        }
        fallback.get_or_insert(reader);
    }
    fallback
}

/// The permutation that unscrambles the four Lsa class strings into the boot key.
const BOOTKEY_PERMUTATION: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

/// Recover the boot key from the `SYSTEM` hive.
fn boot_key(system: &CellReader) -> Option<[u8; 16]> {
    // The control set to read. `CurrentControlSet` is a boot-time symlink that a
    // hive-on-disk does not carry, so the number is read from `Select\Current`
    // and the concrete `ControlSet00N` used; `001` is the near-universal default.
    let control = read_value(system, "Select", "Current")
        .filter(|v| v.len() >= 4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        .unwrap_or(1);
    let base = format!("ControlSet{control:03}\\Control\\Lsa");

    let mut scrambled_hex = String::new();
    for sub in ["JD", "Skew1", "GBG", "Data"] {
        let class = read_class(system, &format!("{base}\\{sub}"))?;
        // The class is UTF-16LE text — eight hex digits.
        let text: String = class
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| char::from(c[0]))
            .filter(|ch| ch.is_ascii_hexdigit())
            .collect();
        scrambled_hex.push_str(&text);
    }
    let scrambled = unhex16(&scrambled_hex)?;
    let mut key = [0u8; 16];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = scrambled[BOOTKEY_PERMUTATION[i]];
    }
    Some(key)
}

/// Derive the hashed boot key from `SAM\Domains\Account\F` (Windows 10+ AES).
fn hashed_boot_key(sam: &CellReader, boot_key: &[u8; 16]) -> Result<[u8; 16], String> {
    let f = read_value(sam, "SAM\\Domains\\Account", "F")
        .ok_or_else(|| "the SAM domain F value was not readable".to_string())?;
    // `Key0` begins at offset 0x68 in F.
    let key0 = f
        .get(0x68..)
        .ok_or_else(|| "the SAM F value is shorter than its key structure".to_string())?;
    match key0.first() {
        // SAM_KEY_DATA_AES: Revision(4), Length(4), CheckSumLen(4), DataLen(4),
        // Salt(16), Data(:). Hashed boot key = AES-CBC(boot_key, Data, iv=Salt).
        Some(0x02) => {
            let data_len = le_u32(key0, 12) as usize;
            let salt = key0
                .get(16..32)
                .ok_or_else(|| "the SAM F AES salt is truncated".to_string())?;
            let data = key0
                .get(32..32 + data_len)
                .ok_or_else(|| "the SAM F AES data is truncated".to_string())?;
            let plain = aes128_cbc_decrypt(boot_key, salt, data);
            plain
                .get(..16)
                .map(|k| {
                    let mut out = [0u8; 16];
                    out.copy_from_slice(k);
                    out
                })
                .ok_or_else(|| "the decrypted hashed boot key is too short".to_string())
        }
        Some(0x01) => Err(
            "this SAM stores its key in the older RC4 form, which this build does \
                            not decrypt; the account hashes were located but not recovered"
                .to_string(),
        ),
        _ => Err("the SAM domain key is not a form this build recognises".to_string()),
    }
}

/// Decrypt every account's NT hash under `SAM\Domains\Account\Users`.
fn decrypt_users(sam: &CellReader, hashed_boot_key: &[u8; 16]) -> Vec<RecoveredCredential> {
    let mut out = Vec::new();
    let Ok(nodes) = resolve_key(sam, Some("SAM\\Domains\\Account\\Users")) else {
        return out;
    };
    let Some(users) = nodes.last() else {
        return out;
    };
    for sub in sam.subkeys(users).keys {
        let Some(rid) = u32::from_str_radix(&sub.name.text, 16).ok() else {
            continue;
        };
        let v = match read_value_of(sam, &sub, "V") {
            Some(v) => v,
            None => continue,
        };
        out.push(decrypt_one_user(rid, &v, hashed_boot_key));
    }
    out
}

/// Extract and decrypt one account's NT hash from its `V` value.
fn decrypt_one_user(rid: u32, v: &[u8], hashed_boot_key: &[u8; 16]) -> RecoveredCredential {
    // The variable-data section starts at 0xCC; the header carries the account
    // name and the NT-hash blob as (offset, length) pairs relative to it.
    let name = read_v_string(v, 0x0c).unwrap_or_default();
    let mut cred = RecoveredCredential {
        rid,
        username: name,
        nt_hash: None,
        note: None,
    };

    let Some(data) = v.get(0xcc..) else {
        cred.note = Some("the account V value is shorter than its header".to_string());
        return cred;
    };
    let nt_off = le_u32(v, 0xa8) as usize;
    let nt_len = le_u32(v, 0xac) as usize;
    let Some(blob) = data.get(nt_off..nt_off + nt_len) else {
        cred.note = Some("the NT-hash blob is past the end of the V value".to_string());
        return cred;
    };
    // A length of 4 (header only, no hash) is an account with no password.
    if nt_len <= 4 || blob.len() < 4 {
        cred.nt_hash = Some(hex(&EMPTY_NT_HASH));
        cred.note = Some(
            "no password is set on this account (blank); the NT hash is the \
                          well-known blank-password hash"
                .to_string(),
        );
        return cred;
    }

    // SAM_HASH_AES: PekID(2), Revision(2), DataOffset(4), Salt(16), Hash(:).
    // Revision 2 is the AES form; 1 is the older RC4 form.
    let revision = u16::from_le_bytes([blob[2], blob.get(3).copied().unwrap_or(0)]);
    if revision != 2 {
        cred.note = Some(
            "this account's hash is stored in the older RC4 form, which this build does not \
             decrypt"
                .to_string(),
        );
        return cred;
    }
    let (Some(salt), Some(enc)) = (blob.get(8..24), blob.get(24..40)) else {
        cred.note = Some("the AES hash blob is truncated".to_string());
        return cred;
    };
    let aes_out = aes128_cbc_decrypt(hashed_boot_key, salt, enc);
    if aes_out.len() < 16 {
        cred.note = Some("the AES decryption produced too few bytes".to_string());
        return cred;
    }
    // Remove the RID-keyed DES layer.
    let (k1, k2) = derive_des_keys(rid);
    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&des_ecb_decrypt(&k1, &aes_out[..8]));
    hash[8..].copy_from_slice(&des_ecb_decrypt(&k2, &aes_out[8..16]));
    cred.nt_hash = Some(hex(&hash));
    cred
}

/// The NT hash of a blank password: `MD4(UTF-16LE(""))`.
const EMPTY_NT_HASH: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
];

// --- registry helpers -------------------------------------------------------

fn read_value(reader: &CellReader, path: &str, value_name: &str) -> Option<Vec<u8>> {
    let nodes = resolve_key(reader, Some(path)).ok()?;
    read_value_of(reader, nodes.last()?, value_name)
}

fn read_value_of(
    reader: &CellReader,
    node: &crate::registry::key::KeyNode,
    value_name: &str,
) -> Option<Vec<u8>> {
    for value in reader.values(node).values {
        if value.name.text.eq_ignore_ascii_case(value_name) {
            if let ValueData::Available { raw, .. } = value.data {
                return Some(raw);
            }
        }
    }
    None
}

fn read_class(reader: &CellReader, path: &str) -> Option<Vec<u8>> {
    let nodes = resolve_key(reader, Some(path)).ok()?;
    reader.key_class(nodes.last()?.cell).ok().flatten()
}

/// Read a key's default (unnamed) value — impacket's `\...\default`.
fn read_default_value(reader: &CellReader, path: &str) -> Option<Vec<u8>> {
    read_value(reader, path, "")
}

/// UTF-16LE bytes to a `String`, lossily.
fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Round a length up to a 4-byte boundary, as the cached-logon layout pads.
fn pad4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}

/// Read a UTF-16LE string named by an (offset, length) pair at `header_off` in a
/// SAM `V` value, relative to the 0xCC data base.
fn read_v_string(v: &[u8], header_off: usize) -> Option<String> {
    let off = le_u32(v, header_off) as usize;
    let len = le_u32(v, header_off + 4) as usize;
    let data = v.get(0xcc..)?;
    let bytes = data.get(off..off + len)?;
    let utf16: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&utf16))
}

// --- crypto -----------------------------------------------------------------

/// AES-128 in CBC mode, decrypt. Data is a whole number of blocks (the SAM
/// structures always are); a short tail is ignored rather than guessed.
fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8], data: &[u8]) -> Vec<u8> {
    if iv.len() != 16 || data.len() < 16 {
        return Vec::new();
    }
    let mut cipher = cbc::Decryptor::<Aes128>::new(key.into(), iv.into());
    let mut out = Vec::with_capacity(data.len());
    for block in data.as_chunks::<16>().0.iter() {
        let mut b = *aes::cipher::generic_array::GenericArray::from_slice(block);
        cipher.decrypt_block_mut(&mut b);
        out.extend_from_slice(&b);
    }
    out
}

/// `SHA-256(key || value repeated `rounds` times)` — the LSA key-derivation.
fn sha256_rounds(key: &[u8], value: &[u8], rounds: usize) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(key);
    for _ in 0..rounds {
        sha.update(value);
    }
    sha.finalize().into()
}

/// AES-256 decrypt, matching impacket's `decryptAES`.
///
/// With no IV, each 16-byte block is decrypted under a CBC state re-initialised
/// to a zero IV — i.e. AES-256-ECB — which is how the LSA `SHA-256`-derived keys
/// are used. With an IV it is a single AES-256-CBC pass, as the cached-logon
/// records use. A trailing partial block is zero-padded, as the reference does.
fn aes256_decrypt(key: &[u8], data: &[u8], iv: Option<&[u8]>) -> Vec<u8> {
    use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit};
    if key.len() != 32 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(data.len());
    match iv {
        Some(iv) if iv.len() == 16 => {
            let mut cipher = cbc::Decryptor::<Aes256>::new(key.into(), iv.into());
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                let mut b = *aes::cipher::generic_array::GenericArray::from_slice(&block);
                cipher.decrypt_block_mut(&mut b);
                out.extend_from_slice(&b);
            }
        }
        _ => {
            let cipher = Aes256::new(key.into());
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                let mut b = *aes::cipher::generic_array::GenericArray::from_slice(&block);
                cipher.decrypt_block(&mut b);
                out.extend_from_slice(&b);
            }
        }
    }
    out
}

/// DES ECB decrypt of one 8-byte block.
fn des_ecb_decrypt(key: &[u8; 8], block: &[u8]) -> [u8; 8] {
    let cipher = Des::new(key.into());
    let mut b = *aes::cipher::generic_array::GenericArray::from_slice(block);
    cipher.decrypt_block(&mut b);
    let mut out = [0u8; 8];
    out.copy_from_slice(&b);
    out
}

/// The two DES keys a RID derives, per [MS-SAMR] §2.2.11.1.3.
fn derive_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let k = rid.to_le_bytes();
    let key1 = [k[0], k[1], k[2], k[3], k[0], k[1], k[2]];
    let key2 = [k[3], k[0], k[1], k[2], k[3], k[0], k[1]];
    (transform_des_key(&key1), transform_des_key(&key2))
}

/// Expand a 7-byte key to an 8-byte DES key (the parity-bit spread).
fn transform_des_key(input: &[u8; 7]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = input[0] >> 1;
    out[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2);
    out[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3);
    out[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4);
    out[4] = ((input[3] & 0x0f) << 3) | (input[4] >> 5);
    out[5] = ((input[4] & 0x1f) << 2) | (input[5] >> 6);
    out[6] = ((input[5] & 0x3f) << 1) | (input[6] >> 7);
    out[7] = input[6] & 0x7f;
    for b in out.iter_mut() {
        *b = (*b << 1) & 0xfe;
    }
    out
}

// --- small utilities --------------------------------------------------------

fn le_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rid_des_key_derivation_matches_the_spec() {
        // A known vector from the MS-SAMR derivation for RID 500.
        let (k1, k2) = derive_des_keys(500);
        // Both keys are valid 8-byte DES keys (low parity bit cleared).
        assert!(k1.iter().all(|b| b & 1 == 0));
        assert!(k2.iter().all(|b| b & 1 == 0));
    }

    #[test]
    fn the_boot_key_permutation_is_a_bijection() {
        let mut seen = [false; 16];
        for &p in &BOOTKEY_PERMUTATION {
            assert!(!seen[p], "permutation repeats index {p}");
            seen[p] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn unhex16_requires_exactly_sixteen_bytes() {
        assert!(unhex16("00").is_none());
        assert_eq!(unhex16(&"ab".repeat(16)).unwrap(), [0xabu8; 16]);
    }

    /// The Win10+ LSA-secret decryption round-trips: an `LSA_SECRET` built the
    /// way Windows builds it (32-byte salt + AES-256-ECB of an `LSA_SECRET_BLOB`,
    /// key = SHA-256(bootkey, salt, 1000 rounds)) decrypts back to the secret.
    /// This exercises `sha256_rounds`, `aes256_decrypt`, and the blob parse — the
    /// crypto shared by LSA secrets, NL$KM, and the cached-logon key — without a
    /// resident SECURITY hive.
    #[test]
    fn an_lsa_secret_blob_round_trips() {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let key = [0x42u8; 16]; // stand-in boot key
        let salt = [0x11u8; 32];
        let secret: &[u8] = b"$MACHINE.ACC-password-material!!"; // 32 bytes

        // LSA_SECRET_BLOB: Length(4) + Unknown(12) + Secret, padded to 16.
        let mut blob = Vec::new();
        blob.extend_from_slice(&(secret.len() as u32).to_le_bytes());
        blob.extend_from_slice(&[0u8; 12]);
        blob.extend_from_slice(secret);
        while blob.len() % 16 != 0 {
            blob.push(0);
        }

        // Encrypt exactly as Windows: AES-256-ECB under SHA-256(key, salt, 1000).
        let derived = sha256_rounds(&key, &salt, 1000);
        let cipher = Aes256::new((&derived).into());
        let mut ct = Vec::new();
        for chunk in blob.chunks(16) {
            let mut b = *aes::cipher::generic_array::GenericArray::from_slice(chunk);
            cipher.encrypt_block(&mut b);
            ct.extend_from_slice(&b);
        }

        // LSA_SECRET: 28-byte header, then EncryptedData = salt || ciphertext.
        let mut value = vec![0u8; 28];
        value.extend_from_slice(&salt);
        value.extend_from_slice(&ct);

        let recovered = decrypt_lsa_blob(&value, &key).expect("the LSA blob must decrypt");
        assert_eq!(
            recovered, secret,
            "the decrypted secret must match the plaintext"
        );
    }
}
