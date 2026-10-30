#![forbid(unsafe_code)]
//! Minimal SQLCipher database decryptor — SQLCipher 3 passphrase / HMAC-SHA1 and
//! SQLCipher 4 raw key / HMAC-SHA512 — with per-page authentication.
//!
//! Some mobile messengers (WeChat, LINE) store their SQLite databases under a
//! SQLCipher layer. Given the passphrase and the app's cipher parameters, this
//! reverses the page encryption and returns the plaintext SQLite bytes, which the
//! caller then opens with an ordinary SQLite reader.
//!
//! # Format (SQLCipher 3, the WeChat/LINE configuration)
//!
//! - The first 16 bytes of the file are the random **salt**.
//! - The **encryption key** = `PBKDF2-HMAC-SHA1(passphrase, salt, kdf_iter, 32)`.
//! - Each page is `page_size` bytes: `[ciphertext][IV (16)][HMAC (20)][pad]`, the
//!   trailing `reserve` bytes (48 with HMAC) being IV+HMAC+padding. Page 1's first
//!   16 bytes hold the salt, so its ciphertext starts at offset 16.
//! - Ciphertext is AES-256-CBC decrypted with the key and that page's IV. On
//!   page 1 the 16-byte SQLite header (`SQLite format 3\0`) is restored.
//!
//! # Integrity
//!
//! **Every page's HMAC is verified** (BUG-012, closed 2026-08-04). For each
//! page the HMAC-SHA1 is recomputed over its ciphertext, its initialisation
//! vector and its 1-based page number, and compared in constant time with the
//! tag the page carries. All three inputs matter:
//!
//! - covering the **ciphertext** catches a page whose contents were altered;
//! - covering the **IV** catches an IV swapped for another, which rewrites the
//!   whole page's plaintext without touching a byte of ciphertext;
//! - covering the **page number** catches two otherwise-valid pages exchanged.
//!   Both are genuine, both were written by the real key, and only their order
//!   is a lie — which in a message store rewrites a conversation.
//!
//! [`Decryption::integrity_verified`] is `true` only when the database carried
//! HMACs *and* every one matched. A database written with
//! `cipher_use_hmac = OFF` reports `false` with [`NO_HMACS_PRESENT`]: there was
//! nothing to check, which is not the same as having checked and passed.
//! Failing pages are named in [`Decryption::failed_pages`], and their plaintext
//! is still returned — withholding it would deny an examiner evidence that may
//! matter; the record simply must not call it sound.
//!
//! ## Why this can be trusted
//!
//! The framing was transcribed from upstream `sqlcipher.c` rather than
//! remembered, and — because a round-trip against this crate's own encryptor
//! would prove only that its two halves agree with each other — it is verified
//! against a database written by **SQLCipher 4.6.1 itself**. See
//! `tests/interop_test.rs`. That test is what makes the HMAC key derivation
//! (encryption key as the password, salt XOR `0x3a`, two iterations) and the
//! authenticated span more than a plausible reading.
//!
//! ## Scope
//!
//! Two forms:
//!
//! - **SQLCipher 3 parameters** ([`decrypt_with_provenance`]): AES-256-CBC,
//!   PBKDF2-HMAC-SHA1 from a passphrase, HMAC-SHA1. That is what WeChat and LINE
//!   use.
//! - **SQLCipher 4 with a raw key** ([`decrypt_v4_raw_key`],
//!   [`decrypt_v4_raw_key_wal`]; module `v4`): no KDF over the key, HMAC-SHA512,
//!   an 80-byte reserve, and optionally a plaintext header. That is what Signal
//!   for iOS writes, and it is graded on the Signal store from the Magnet 2022
//!   iPhone 8 extraction (`tests/signal_ios_real_store.rs`: all 305 pages and 38
//!   WAL frames authenticate, and SQLite opens the result).
//!
//! A SQLCipher 4 **passphrase** (PBKDF2-HMAC-SHA512) is not accepted by either;
//! such a database is refused, not misread.
//!
//! # Safety
//!
//! Decryption is only *cryptographic*; correctness is confirmed by the caller
//! opening the result as SQLite. A wrong key/params yields garbage whose SQLite
//! page-size field won't match — [`decrypt`] returns `None` in that case, and a
//! near-miss that slips through still fails to open as a database. That bounds
//! the *key*, not the *contents*: see the section above.
//!
//! The crypto primitives are covered by known-answer vectors (RFC 6070 for
//! PBKDF2), the framing by a round-trip test, and both together by the
//! interoperability test against SQLCipher's own output. End-to-end
//! confirmation against a real *app* database remains a caller-side gated
//! test — a WeChat store is not something this project holds.

use aes::Aes256;
use cbc::Decryptor;
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use hmac::Hmac;
use md5::{Digest, Md5};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const IV_LEN: usize = 16;
/// Size of the per-page HMAC field: HMAC-SHA1, 20 bytes.
pub const HMAC_LEN: usize = 20;

/// The byte SQLCipher XORs into the database salt to produce the salt its HMAC
/// key is derived from.
///
/// From upstream `sqlcipher.c` (`HMAC_SALT_MASK`). It exists so the HMAC key and
/// the encryption key are not derived from the same salt; getting it wrong
/// produces a key that verifies nothing and rejects every page.
const HMAC_SALT_MASK: u8 = 0x3a;

/// Iterations for deriving the HMAC key from the encryption key.
///
/// Upstream `FAST_PBKDF2_ITER`. Two, not `kdf_iter`: the input is already a
/// derived key rather than a passphrase, so the work factor has been paid.
const FAST_KDF_ITER: u32 = 2;

/// What a report says when every page authenticated.
pub const INTEGRITY_VERIFIED: &str =
    "every page's HMAC-SHA1 was recomputed over its ciphertext, initialisation vector and page \
     number, and matched the value stored on the page; nothing in this database was altered, \
     corrupted or resequenced after it was written";

/// What a report says when the database carries no HMACs to check.
///
/// A database written with `PRAGMA cipher_use_hmac = OFF` has no authentication
/// tags at all. That is a property of the evidence rather than a limit of this
/// reader, and the distinction matters: "not verified because there was nothing
/// to verify against" is a different statement from "verified and failed".
pub const NO_HMACS_PRESENT: &str =
    "this database was written without per-page HMACs (cipher_use_hmac off), so there is no \
     authentication tag to check; nothing here establishes that a page was not altered or \
     corrupted, and only the first page's SQLite header was checked, which speaks to the key \
     rather than to the contents";

/// Retained for callers that referenced it before verification existed.
#[deprecated(
    since = "0.2.0",
    note = "per-page HMACs are now verified; read `Decryption::integrity_statement`, which \
            states what was actually checked for this database"
)]
pub const NO_INTEGRITY_VERIFICATION: &str = NO_HMACS_PRESENT;

/// The sentence for a database in which one or more pages failed to
/// authenticate.
///
/// Deliberately does **not** say the database is worthless. A single failing
/// page in a large store is a finding about that page; the rest still
/// authenticated, and an examiner needs to be told precisely which is which.
fn integrity_failed_statement(failed: &[u32], total: usize) -> String {
    let listed: Vec<String> = failed.iter().take(16).map(u32::to_string).collect();
    let suffix = if failed.len() > 16 {
        format!(" and {} more", failed.len() - 16)
    } else {
        String::new()
    };
    format!(
        "{} of {total} page(s) failed HMAC verification: page(s) {}{suffix}. A page whose HMAC \
         does not match was altered, corrupted, or moved from another position in the database \
         after it was written. The plaintext of those pages is still returned so it can be \
         examined, but nothing recovered from them may be presented as sound. The remaining \
         pages authenticated.",
        failed.len(),
        listed.join(", ")
    )
}

/// A decrypted SQLCipher database, together with what is and is not known about
/// it.
///
/// Exists so that a caller cannot receive plaintext without also receiving the
/// fact that its integrity was not established. [`decrypt`] drops this and is
/// kept for callers that have not been taught to carry it.
#[derive(Debug, Clone)]
pub struct Decryption {
    /// The plaintext SQLite bytes.
    pub plaintext: Vec<u8>,
    /// How many pages were decrypted.
    pub pages: usize,
    /// Whether every page's HMAC was recomputed and matched.
    ///
    /// `true` only when the database carried HMACs **and** every one of them
    /// verified. A database written without HMACs reports `false` with
    /// [`NO_HMACS_PRESENT`] — there was nothing to check, which is not the same
    /// as having checked and passed.
    pub integrity_verified: bool,
    /// What was actually checked, in the examiner's terms.
    pub integrity_statement: String,
    /// 1-based page numbers whose HMAC did not match.
    ///
    /// Empty when every page verified, or when the database carries no HMACs —
    /// which is why it must be read alongside [`Decryption::integrity_verified`]
    /// rather than instead of it.
    ///
    /// The plaintext of a failing page is still returned. Withholding it would
    /// deny an examiner evidence that may matter; the record simply must not
    /// present it as sound.
    pub failed_pages: Vec<u32>,
}

/// SQLCipher cipher parameters for a database.
#[derive(Debug, Clone, Copy)]
pub struct SqlCipherConfig {
    pub page_size: usize,
    pub kdf_iter: u32,
    pub use_hmac: bool,
}

impl SqlCipherConfig {
    /// WeChat Android `EnMicroMsg.db`: 1024-byte pages, 4000 KDF iterations.
    pub fn wechat() -> Self {
        Self {
            page_size: 1024,
            kdf_iter: 4000,
            use_hmac: true,
        }
    }
}

/// The reserve (trailing) bytes per page: IV (+ HMAC), rounded up to the AES
/// block size.
fn reserve(cfg: &SqlCipherConfig) -> usize {
    if cfg.use_hmac {
        let r = IV_LEN + HMAC_LEN;
        r.div_ceil(16) * 16
    } else {
        IV_LEN
    }
}

/// Derive the per-page HMAC key from the encryption key and the database salt.
///
/// Transcribed from upstream `cipher_ctx_key_derive`: PBKDF2 over the *derived
/// encryption key* (not the passphrase), salted with the database salt XORed
/// byte-wise with [`HMAC_SALT_MASK`], for [`FAST_KDF_ITER`] iterations.
///
/// Each of those three details is load-bearing. Feeding the passphrase instead
/// of the key, or the unmasked salt, or `kdf_iter` instead of 2, all produce a
/// well-formed key that authenticates nothing — every page would be reported as
/// tampered, which is a worse failure than not checking at all because it
/// discredits sound evidence.
fn derive_hmac_key(key: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let masked: Vec<u8> = salt.iter().map(|b| b ^ HMAC_SALT_MASK).collect();
    let mut hmac_key = [0u8; 32];
    pbkdf2::pbkdf2::<HmacSha1>(key, &masked, FAST_KDF_ITER, &mut hmac_key);
    hmac_key
}

/// Verify one page's stored HMAC.
///
/// The authenticated span is the page's **ciphertext followed by its IV**, then
/// the 1-based page number as four little-endian bytes. Covering the IV stops it
/// being swapped; covering the page number stops two otherwise-valid pages being
/// exchanged, which would reorder a database without breaking any single page.
///
/// `page` is the whole on-disk page. `content_off` is 16 on page 1, where the
/// salt occupies the first sixteen bytes, and 0 elsewhere.
fn page_hmac_matches(
    hmac_key: &[u8; 32],
    page: &[u8],
    content_off: usize,
    usable: usize,
    page_number: u32,
) -> bool {
    use hmac::Mac;

    let authenticated_end = usable + IV_LEN;
    let hmac_end = authenticated_end + HMAC_LEN;
    if hmac_end > page.len() || content_off >= authenticated_end {
        return false;
    }

    let Ok(mut mac) = HmacSha1::new_from_slice(hmac_key) else {
        return false;
    };
    mac.update(&page[content_off..authenticated_end]);
    mac.update(&page_number.to_le_bytes());
    // `verify_slice` is constant-time, matching upstream's `sqlcipher_memcmp`.
    // A byte-by-byte compare here would leak how much of a forged tag was
    // correct.
    mac.verify_slice(&page[authenticated_end..hmac_end]).is_ok()
}

/// Derive the WeChat passphrase (`substr(md5(imei + uin), 0, 7)`).
pub fn wechat_passphrase(imei: &str, uin: &str) -> Vec<u8> {
    let mut h = Md5::new();
    h.update(imei.as_bytes());
    h.update(uin.as_bytes());
    let digest = h.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()[..7].to_vec()
}

/// Decrypt a SQLCipher database to plaintext SQLite bytes, or `None` if the
/// key/params don't yield a valid SQLite header.
///
/// **The integrity result is dropped.** Prefer [`decrypt_with_provenance`],
/// which hands back the same bytes plus whether every page HMAC verified, so a
/// caller can stamp its records instead of presenting unverified rows as
/// recovered evidence.
pub fn decrypt(db: &[u8], passphrase: &[u8], cfg: &SqlCipherConfig) -> Option<Vec<u8>> {
    decrypt_with_provenance(db, passphrase, cfg).map(|d| d.plaintext)
}

/// Decrypt a SQLCipher database, returning the plaintext **and** what is known
/// about its integrity.
///
/// # What an examiner learns
///
/// The contents of an encrypted messenger database. What they must also be
/// told, and what this return type carries, is that not one page was
/// authenticated: see [`Decryption::integrity_verified`].
///
/// # What a wrong answer looks like
///
/// A conversation in a report, attributed to a suspect, reconstructed out of a
/// page that was altered after the fact — indistinguishable, on the page, from
/// one that was not.
pub fn decrypt_with_provenance(
    db: &[u8],
    passphrase: &[u8],
    cfg: &SqlCipherConfig,
) -> Option<Decryption> {
    let ps = cfg.page_size;
    if ps < 512 || !ps.is_multiple_of(16) || db.len() < ps {
        return None;
    }
    let reserve = reserve(cfg);
    if reserve >= ps {
        return None;
    }
    let usable = ps - reserve; // ciphertext ends here; the reserve follows
    if usable <= 16 || !usable.is_multiple_of(16) || usable + IV_LEN > ps {
        return None;
    }

    let salt = &db[0..16];
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<HmacSha1>(passphrase, salt, cfg.kdf_iter, &mut key);

    // A non-page-aligned tail means the ciphertext is truncated: a SQLCipher
    // database is always a whole number of pages, so a remainder is a partial
    // last page that cannot be decrypted. Fail closed rather than silently drop
    // it and open a database missing its last page (BUG-174). Cryptographic
    // integrity (HMAC) is still not verified -- that remains BUG-012.
    if !db.len().is_multiple_of(ps) {
        return None;
    }
    let num_pages = db.len() / ps;
    // Derived once: the same HMAC key authenticates every page.
    let hmac_key = cfg.use_hmac.then(|| derive_hmac_key(&key, salt));
    let mut failed_pages: Vec<u32> = Vec::new();

    let mut out = Vec::with_capacity(num_pages * ps);
    for i in 0..num_pages {
        let page = &db[i * ps..(i + 1) * ps];
        let content_off = if i == 0 { 16 } else { 0 };

        // Verified before decryption, as upstream does: a page that does not
        // authenticate should not have its plaintext trusted, and checking
        // first keeps the two facts about the page in one place.
        if let Some(hmac_key) = hmac_key.as_ref() {
            let page_number = (i as u32) + 1; // SQLite page numbers are 1-based
            if !page_hmac_matches(hmac_key, page, content_off, usable, page_number) {
                failed_pages.push(page_number);
            }
        }
        // Ciphertext is [content_off..usable); the IV heads the reserve region.
        let iv: [u8; 16] = page[usable..usable + IV_LEN].try_into().ok()?;
        if usable <= content_off {
            return None;
        }
        let ct = &page[content_off..usable];
        if !ct.len().is_multiple_of(16) {
            return None;
        }
        let mut buf = ct.to_vec();
        let pt = Decryptor::<Aes256>::new(&key.into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .ok()?;

        let mut page_out = vec![0u8; ps];
        if i == 0 {
            page_out[0..16].copy_from_slice(SQLITE_HEADER);
            page_out[16..16 + pt.len()].copy_from_slice(pt);
        } else {
            page_out[0..pt.len()].copy_from_slice(pt);
        }
        out.extend_from_slice(&page_out);
    }

    // Validate: the decrypted SQLite header's page-size field (bytes 16-17, BE)
    // must equal the configured page size. Wrong key/params -> mismatch -> None.
    let hdr_ps = u16::from_be_bytes([out[16], out[17]]) as usize;
    let expected = if ps == 65536 { 1 } else { ps };
    if hdr_ps != expected && !(ps == 65536 && hdr_ps == 1) {
        return None;
    }
    // The header check above speaks to the key. What follows speaks to the
    // contents, which is the distinction BUG-012 existed to close.
    let (integrity_verified, integrity_statement) = match (&hmac_key, failed_pages.is_empty()) {
        (None, _) => (false, NO_HMACS_PRESENT.to_string()),
        (Some(_), true) => (true, INTEGRITY_VERIFIED.to_string()),
        (Some(_), false) => (false, integrity_failed_statement(&failed_pages, num_pages)),
    };

    Some(Decryption {
        plaintext: out,
        pages: num_pages,
        integrity_verified,
        integrity_statement,
        failed_pages,
    })
}

mod v4;
pub use v4::{
    decrypt_v4_raw_key, decrypt_v4_raw_key_wal, encrypt_v4_raw_key_for_test, KeySpecError,
    RawKeySpec, SqlCipher4Config, WalDecryption, HMAC_SHA512_LEN, INTEGRITY_VERIFIED_SHA512,
};

/// Encrypt plaintext SQLite bytes into a SQLCipher database — **for tests only**
/// (deterministic IVs), so the round-trip can validate [`decrypt`]'s framing.
#[doc(hidden)]
pub fn encrypt_for_test(
    plaintext: &[u8],
    passphrase: &[u8],
    salt: &[u8; 16],
    cfg: &SqlCipherConfig,
) -> Vec<u8> {
    use cipher::{block_padding::NoPadding as NP, BlockEncryptMut};
    type Enc = cbc::Encryptor<Aes256>;

    let ps = cfg.page_size;
    let reserve = reserve(cfg);
    let usable = ps - reserve;

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<HmacSha1>(passphrase, salt, cfg.kdf_iter, &mut key);

    let num_pages = plaintext.len() / ps;
    let mut out = Vec::with_capacity(plaintext.len());
    for i in 0..num_pages {
        let page = &plaintext[i * ps..(i + 1) * ps];
        let content_off = if i == 0 { 16 } else { 0 };
        // Deterministic per-page IV (test only).
        let mut iv = [0u8; 16];
        iv[0..4].copy_from_slice(&(i as u32).to_le_bytes());

        let content = &page[content_off..usable];
        let mut buf = vec![0u8; content.len()];
        let ct = Enc::new(&key.into(), &iv.into())
            .encrypt_padded_b2b_mut::<NP>(content, &mut buf)
            .unwrap();

        let mut page_out = vec![0u8; ps];
        if i == 0 {
            page_out[0..16].copy_from_slice(salt);
        }
        page_out[content_off..usable].copy_from_slice(ct);
        page_out[usable..usable + IV_LEN].copy_from_slice(&iv);

        // The HMAC, written the way upstream writes it. Before verification
        // existed this region was left zero, which was harmless only because
        // nothing read it.
        if cfg.use_hmac {
            use hmac::Mac;
            let hmac_key = derive_hmac_key(&key, salt);
            let page_number = (i as u32) + 1;
            let mut mac = HmacSha1::new_from_slice(&hmac_key).expect("HMAC accepts any key length");
            mac.update(&page_out[content_off..usable + IV_LEN]);
            mac.update(&page_number.to_le_bytes());
            let tag = mac.finalize().into_bytes();
            page_out[usable + IV_LEN..usable + IV_LEN + HMAC_LEN].copy_from_slice(&tag);
        }
        out.extend_from_slice(&page_out);
    }
    out
}

#[cfg(test)]
mod tests;
