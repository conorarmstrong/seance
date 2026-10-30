//! SQLCipher 4 with a **raw key**: the form Signal for iOS writes (HUNT-183).
//!
//! # What differs from SQLCipher 3
//!
//! - **No key derivation for the encryption key.** A raw key spec
//!   (`PRAGMA key = "x'…'"`) is used as the AES-256 key as given; PBKDF2 is not
//!   run over it. A 48-byte spec is the 32-byte key followed by the 16-byte
//!   salt; a 32-byte spec leaves the salt to the file's first 16 bytes.
//! - **HMAC-SHA512**, not HMAC-SHA1. The tag is 64 bytes, so the per-page
//!   reserve is 16 (IV) + 64 = 80 bytes — the `0x50` Signal's header carries.
//!   The HMAC key is `PBKDF2-HMAC-SHA512(key, salt XOR 0x3a, 2 iterations, 32)`,
//!   the same construction as SQLCipher 3 with SHA-512 in place of SHA-1; the
//!   authenticated span is unchanged (ciphertext, IV, 1-based page number
//!   little-endian).
//! - **An optional plaintext header** (`cipher_plaintext_header_size`). Signal
//!   for iOS sets it to 32, so the file opens with a genuine SQLite header and
//!   page 1's ciphertext starts at byte 32. The salt is then nowhere in the file,
//!   which is why such a store needs the 48-byte spec.
//!
//! # Why the plaintext header needs its own key check
//!
//! SQLCipher 3's wrong-key check is the decrypted header's page-size field.
//! Behind a plaintext header those bytes were never encrypted and match under
//! any key, so a wrong key would sail through and return noise under a genuine
//! header. Here the check is made on bytes that *were* encrypted: the twenty
//! bytes at 72..92 that SQLite requires to be zero, the schema format number
//! (0..=4) and the text encoding (0..=3). Random bytes pass that with odds below
//! 2^-160.
//!
//! # The write-ahead log
//!
//! Signal's newest writes are in `signal.sqlite-wal`, whose frames carry pages
//! encrypted exactly like the store's. [`decrypt_v4_raw_key_wal`] decrypts the
//! frames SQLite would replay — those up to the last commit frame in the valid
//! checksum chain — and returns them as a plaintext WAL whose checksums are
//! recomputed over the plaintext, so an ordinary SQLite opens the pair and
//! replays it as it would have on the device. Frames after that point (an
//! uncommitted transaction, or frames left from an earlier generation of the
//! log) are **counted and not presented**: SQLite would not replay them either,
//! and recovering them is a separate, unbuilt capability.
//!
//! # Scope
//!
//! Raw keys only. A SQLCipher 4 passphrase (PBKDF2-HMAC-SHA512, 256,000
//! iterations by default) is not accepted here. AES-256-CBC only.
//!
//! # Key material
//!
//! [`RawKeySpec`] holds the key. Its `Debug` prints `<redacted>`, it has no
//! `Display`, `Clone` or `Serialize`, and its bytes — and every copy this module
//! makes of them — are zeroed when dropped. Nothing in this module logs.

use aes::Aes256;
use cbc::Decryptor;
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::{
    integrity_failed_statement, Decryption, FAST_KDF_ITER, HMAC_SALT_MASK, IV_LEN, SQLITE_HEADER,
};

type HmacSha512 = Hmac<Sha512>;

/// Size of a SQLCipher 4 per-page HMAC field: HMAC-SHA512, 64 bytes.
pub const HMAC_SHA512_LEN: usize = 64;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;

/// What a report says when every page of a SQLCipher 4 store authenticated.
pub const INTEGRITY_VERIFIED_SHA512: &str =
    "every page's HMAC-SHA512 was recomputed over its ciphertext, initialisation vector and page \
     number, and matched the value stored on the page; nothing in this database was altered, \
     corrupted or resequenced after it was written";

/// Why a key spec was not accepted. Carries lengths, never bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySpecError {
    /// A raw key spec is 32 bytes (key) or 48 bytes (key then salt).
    WrongLength(usize),
    /// Not of the form `x'<hex>'`.
    NotAHexLiteral,
}

impl std::fmt::Display for KeySpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength(n) => write!(
                f,
                "a SQLCipher raw key spec is 32 bytes (key) or 48 bytes (key then salt); \
                 this one is {n}"
            ),
            Self::NotAHexLiteral => f.write_str("a SQLCipher raw key spec is written x'<hex>'"),
        }
    }
}

impl std::error::Error for KeySpecError {}

/// A SQLCipher raw key spec: the 32-byte AES key and, when given, the 16-byte
/// database salt.
///
/// Redacted in `Debug`, not `Clone`, and zeroed on drop.
pub struct RawKeySpec {
    key: [u8; KEY_LEN],
    salt: Option<[u8; SALT_LEN]>,
}

impl RawKeySpec {
    /// From the raw bytes, as a keychain item's `v_Data` carries them: 32
    /// bytes of key, or 48 bytes of key then salt.
    pub fn from_bytes(spec: &[u8]) -> Result<Self, KeySpecError> {
        let mut key = [0u8; KEY_LEN];
        match spec.len() {
            KEY_LEN => {
                key.copy_from_slice(spec);
                Ok(Self { key, salt: None })
            }
            48 => {
                key.copy_from_slice(&spec[..KEY_LEN]);
                let mut salt = [0u8; SALT_LEN];
                salt.copy_from_slice(&spec[KEY_LEN..]);
                Ok(Self {
                    key,
                    salt: Some(salt),
                })
            }
            n => Err(KeySpecError::WrongLength(n)),
        }
    }

    /// From the SQL literal SQLCipher takes: `x'<64 or 96 hex digits>'`.
    pub fn from_sql_literal(literal: &str) -> Result<Self, KeySpecError> {
        let t = literal.trim();
        let hex = t
            .strip_prefix("x'")
            .or_else(|| t.strip_prefix("X'"))
            .and_then(|r| r.strip_suffix('\''))
            .ok_or(KeySpecError::NotAHexLiteral)?;
        if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(KeySpecError::NotAHexLiteral);
        }
        let mut bytes: Vec<u8> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| (hex_val(p[0]) << 4) | hex_val(p[1]))
            .collect();
        let spec = Self::from_bytes(&bytes);
        bytes.zeroize();
        spec
    }

    /// From what an examiner types: the SQL literal `x'<hex>'`, or the bare
    /// 64 or 96 hex digits. Whitespace around it is ignored; nothing else is
    /// accepted, and the error carries no byte of the input.
    pub fn from_text(text: &str) -> Result<Self, KeySpecError> {
        let t = text.trim();
        if t.starts_with("x'") || t.starts_with("X'") {
            return Self::from_sql_literal(t);
        }
        if !t.len().is_multiple_of(2) || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(KeySpecError::NotAHexLiteral);
        }
        let mut bytes: Vec<u8> = t
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| (hex_val(p[0]) << 4) | hex_val(p[1]))
            .collect();
        let spec = Self::from_bytes(&bytes);
        bytes.zeroize();
        spec
    }

    /// Whether the spec carries the database salt (the 48-byte form).
    pub fn has_salt(&self) -> bool {
        self.salt.is_some()
    }
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

impl Drop for RawKeySpec {
    fn drop(&mut self) {
        self.key.zeroize();
        if let Some(s) = self.salt.as_mut() {
            s.zeroize();
        }
    }
}

impl std::fmt::Debug for RawKeySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawKeySpec")
            .field("key", &format_args!("<redacted>"))
            .field(
                "salt",
                &format_args!(
                    "{}",
                    if self.has_salt() {
                        "<redacted>"
                    } else {
                        "absent"
                    }
                ),
            )
            .finish()
    }
}

/// SQLCipher 4 cipher parameters for a raw-key database.
#[derive(Debug, Clone, Copy)]
pub struct SqlCipher4Config {
    pub page_size: usize,
    /// `cipher_plaintext_header_size`: 0 (the salt is in the file's first 16
    /// bytes) or a multiple of 16 left unencrypted at the start of page 1.
    pub plaintext_header_size: usize,
    pub use_hmac: bool,
}

impl SqlCipher4Config {
    /// Signal for iOS `grdb/signal.sqlite`: 4096-byte pages, a 32-byte
    /// plaintext header, HMAC-SHA512. Measured on the Magnet 2022 iPhone 8
    /// store, not taken from documentation.
    pub fn signal_ios() -> Self {
        Self {
            page_size: 4096,
            plaintext_header_size: 32,
            use_hmac: true,
        }
    }

    fn reserve(&self) -> usize {
        if self.use_hmac {
            (IV_LEN + HMAC_SHA512_LEN).div_ceil(16) * 16
        } else {
            IV_LEN
        }
    }
}

/// The derived state for one database: the AES key, the HMAC key and the
/// page-1 layout. Zeroed on drop.
struct Cipher4 {
    key: [u8; KEY_LEN],
    hmac_key: Option<[u8; 32]>,
    page_size: usize,
    usable: usize,
    /// Bytes of page 1 that are not ciphertext: the salt (16) or the plaintext
    /// header.
    page1_offset: usize,
    plaintext_header: bool,
}

impl Drop for Cipher4 {
    fn drop(&mut self) {
        self.key.zeroize();
        if let Some(k) = self.hmac_key.as_mut() {
            k.zeroize();
        }
    }
}

impl Cipher4 {
    /// `None` for parameters no SQLCipher 4 database can have, or when the
    /// salt the HMAC key needs is nowhere to be had.
    fn new(key: &RawKeySpec, salt: Option<[u8; SALT_LEN]>, cfg: &SqlCipher4Config) -> Option<Self> {
        let ps = cfg.page_size;
        if !(512..=65_536).contains(&ps) || !ps.is_power_of_two() {
            return None;
        }
        let usable = ps.checked_sub(cfg.reserve())?;
        let hdr = cfg.plaintext_header_size;
        if hdr != 0 && (!hdr.is_multiple_of(16) || hdr < 32 || hdr >= usable) {
            return None;
        }
        let hmac_key = if cfg.use_hmac {
            let salt = salt?;
            let masked: Vec<u8> = salt.iter().map(|b| b ^ HMAC_SALT_MASK).collect();
            let mut k = [0u8; 32];
            pbkdf2::pbkdf2::<HmacSha512>(&key.key, &masked, FAST_KDF_ITER, &mut k);
            Some(k)
        } else {
            None
        };
        Some(Self {
            key: key.key,
            hmac_key,
            page_size: ps,
            usable,
            page1_offset: if hdr == 0 { SALT_LEN } else { hdr },
            plaintext_header: hdr != 0,
        })
    }

    /// Decrypt one on-disk page image (from the store or a WAL frame).
    /// Returns the plaintext page and whether its HMAC matched (`true` when
    /// the database carries none — the caller states that separately).
    fn open_page(&self, page: &[u8], page_number: u32) -> Option<(Vec<u8>, bool)> {
        let off = if page_number == 1 {
            self.page1_offset
        } else {
            0
        };
        let iv_end = self.usable + IV_LEN;
        if page.len() != self.page_size || off >= self.usable {
            return None;
        }
        let authentic = match &self.hmac_key {
            None => true,
            Some(hk) => {
                let mut mac = <HmacSha512 as Mac>::new_from_slice(hk).ok()?;
                mac.update(&page[off..iv_end]);
                mac.update(&page_number.to_le_bytes());
                // Constant-time, as upstream's `sqlcipher_memcmp`.
                mac.verify_slice(&page[iv_end..iv_end + HMAC_SHA512_LEN])
                    .is_ok()
            }
        };
        let iv: [u8; IV_LEN] = page[self.usable..iv_end].try_into().ok()?;
        let mut buf = page[off..self.usable].to_vec();
        Decryptor::<Aes256>::new(&self.key.into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .ok()?;
        let mut out = vec![0u8; self.page_size];
        if page_number == 1 {
            if self.plaintext_header {
                out[..off].copy_from_slice(&page[..off]);
            } else {
                out[..SQLITE_HEADER.len()].copy_from_slice(SQLITE_HEADER);
            }
        }
        out[off..self.usable].copy_from_slice(&buf);
        buf.zeroize();
        Some((out, authentic))
    }
}

/// Whether a decrypted page 1 is one SQLite would accept, judged on bytes that
/// were encrypted (see the module documentation).
fn page_one_is_sqlite(p: &[u8], cfg: &SqlCipher4Config) -> bool {
    let be32 = |o: usize| u32::from_be_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]]);
    let page_size_field = u16::from_be_bytes([p[16], p[17]]) as usize;
    let page_size_ok =
        page_size_field == cfg.page_size || (cfg.page_size == 65_536 && page_size_field == 1);
    page_size_ok
        && p[20] as usize == cfg.reserve()
        && p[72..92].iter().all(|&b| b == 0)
        && be32(44) <= 4
        && be32(56) <= 3
}

/// Decrypt a SQLCipher 4 database under a raw key, returning the plaintext
/// **and** what is known about its integrity.
///
/// `None` when the parameters are not ones this file can have, when the key
/// is wrong, when a 48-byte spec's salt is not the file's, when a
/// plaintext-header store is given a key spec with no salt (its HMAC key
/// cannot be derived), or when the file is not a whole number of pages.
pub fn decrypt_v4_raw_key(
    db: &[u8],
    key: &RawKeySpec,
    cfg: &SqlCipher4Config,
) -> Option<Decryption> {
    let ps = cfg.page_size;
    if db.len() < ps || ps == 0 || !db.len().is_multiple_of(ps) {
        return None;
    }
    let salt = if cfg.plaintext_header_size == 0 {
        let file_salt: [u8; SALT_LEN] = db[..SALT_LEN].try_into().ok()?;
        if key.salt.is_some_and(|s| s != file_salt) {
            return None;
        }
        Some(file_salt)
    } else {
        // A plaintext header must be a SQLite header that declares this
        // layout; otherwise this is not the store the parameters describe.
        if &db[..16] != SQLITE_HEADER {
            return None;
        }
        key.salt
    };
    let c = Cipher4::new(key, salt, cfg)?;

    let num_pages = db.len() / ps;
    let mut out = Vec::with_capacity(db.len());
    let mut failed_pages = Vec::new();
    for (i, page) in db.chunks_exact(ps).enumerate() {
        let page_number = u32::try_from(i + 1).ok()?;
        let (plain, authentic) = c.open_page(page, page_number)?;
        if i == 0 && !page_one_is_sqlite(&plain, cfg) {
            return None; // the key is wrong
        }
        if !authentic {
            failed_pages.push(page_number);
        }
        out.extend_from_slice(&plain);
    }

    let (integrity_verified, integrity_statement) =
        match (c.hmac_key.is_some(), failed_pages.is_empty()) {
            (false, _) => (false, crate::NO_HMACS_PRESENT.to_string()),
            (true, true) => (true, INTEGRITY_VERIFIED_SHA512.to_string()),
            (true, false) => (false, integrity_failed_statement(&failed_pages, num_pages)),
        };
    Some(Decryption {
        plaintext: out,
        pages: num_pages,
        integrity_verified,
        integrity_statement,
        failed_pages,
    })
}

/// A decrypted SQLCipher 4 write-ahead log.
#[derive(Debug, Clone)]
pub struct WalDecryption {
    /// A WAL SQLite can replay beside the decrypted store: the original
    /// 32-byte header, then the committed frames with their pages decrypted
    /// and their checksum chain recomputed over the plaintext.
    pub plaintext_wal: Vec<u8>,
    /// Whole frames in the file.
    pub frames_in_file: usize,
    /// Frames up to and including the last commit frame of the valid chain —
    /// what SQLite replays, and what `plaintext_wal` carries.
    pub frames_committed: usize,
    /// Frames after that point, counted and not presented.
    pub frames_not_committed: usize,
    /// Whether every committed frame's HMAC matched. `false` when there were
    /// no committed frames or no HMACs: nothing was checked.
    pub integrity_verified: bool,
    pub integrity_statement: String,
    /// 1-based frame indexes whose HMAC did not match. Their plaintext is
    /// still in `plaintext_wal`, as with [`Decryption::failed_pages`].
    pub failed_frames: Vec<u32>,
    /// What was and was not presented, in the examiner's terms.
    pub wal_statement: String,
}

const WAL_HEADER: usize = 32;
const WAL_FRAME_HEADER: usize = 24;
const WAL_VERSION: u32 = 3_007_000;

/// SQLite's WAL checksum (`walChecksumBytes`): two running 32-bit sums over
/// 8-byte steps, words read in the byte order the magic declares.
fn wal_checksum(big_endian: bool, data: &[u8], init: (u32, u32)) -> (u32, u32) {
    let (mut s0, mut s1) = init;
    for w in data.as_chunks::<8>().0 {
        let word = |b: &[u8]| {
            let a = [b[0], b[1], b[2], b[3]];
            if big_endian {
                u32::from_be_bytes(a)
            } else {
                u32::from_le_bytes(a)
            }
        };
        s0 = s0.wrapping_add(word(&w[0..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(word(&w[4..8])).wrapping_add(s0);
    }
    (s0, s1)
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Decrypt the frames of a SQLCipher 4 write-ahead log that SQLite would
/// replay.
///
/// The frame chain is validated on the file **as written** (salts and
/// cumulative checksums over the ciphertext, as SQLite validates it), each
/// committed frame's page is decrypted and its HMAC checked against the page
/// number the frame names, and the result is re-chained over the plaintext.
///
/// `None` when the log's header is not a SQLite WAL header for this page size
/// or its checksum does not match (SQLite would ignore the whole log), or when
/// the key spec carries no salt and HMACs are in use.
pub fn decrypt_v4_raw_key_wal(
    wal: &[u8],
    key: &RawKeySpec,
    cfg: &SqlCipher4Config,
) -> Option<WalDecryption> {
    let ps = cfg.page_size;
    if wal.len() < WAL_HEADER {
        return None;
    }
    let magic = be32(wal, 0);
    if magic & !1 != 0x377f_0682 || be32(wal, 4) != WAL_VERSION || be32(wal, 8) as usize != ps {
        return None;
    }
    let big_endian = magic & 1 == 1;
    let header_ck = wal_checksum(big_endian, &wal[..24], (0, 0));
    if header_ck != (be32(wal, 24), be32(wal, 28)) {
        return None;
    }
    let c = Cipher4::new(key, key.salt, cfg)?;

    let frame_len = WAL_FRAME_HEADER + ps;
    let frames_in_file = (wal.len() - WAL_HEADER) / frame_len;
    let trailing_bytes = (wal.len() - WAL_HEADER) % frame_len;

    // Walk the chain as SQLite's recovery does: stop at the first frame whose
    // salts or checksum do not continue it; what SQLite replays ends at the
    // last commit frame before that point.
    let mut ck = header_ck;
    let mut committed = 0usize;
    for i in 0..frames_in_file {
        let f = &wal[WAL_HEADER + i * frame_len..WAL_HEADER + (i + 1) * frame_len];
        if be32(f, 0) == 0 || f[8..16] != wal[16..24] {
            break;
        }
        let next = wal_checksum(
            big_endian,
            &f[WAL_FRAME_HEADER..],
            wal_checksum(big_endian, &f[..8], ck),
        );
        if next != (be32(f, 16), be32(f, 20)) {
            break;
        }
        ck = next;
        if be32(f, 4) != 0 {
            committed = i + 1;
        }
    }

    let mut out = wal[..WAL_HEADER].to_vec();
    let mut ck = header_ck;
    let mut failed_frames = Vec::new();
    for i in 0..committed {
        let f = &wal[WAL_HEADER + i * frame_len..WAL_HEADER + (i + 1) * frame_len];
        let page_number = be32(f, 0);
        let (plain, authentic) = c.open_page(&f[WAL_FRAME_HEADER..], page_number)?;
        if !authentic {
            failed_frames.push(u32::try_from(i + 1).ok()?);
        }
        ck = wal_checksum(big_endian, &plain, wal_checksum(big_endian, &f[..8], ck));
        out.extend_from_slice(&f[..16]);
        out.extend_from_slice(&ck.0.to_be_bytes());
        out.extend_from_slice(&ck.1.to_be_bytes());
        out.extend_from_slice(&plain);
    }

    let not_committed = frames_in_file - committed;
    let (integrity_verified, integrity_statement) = if c.hmac_key.is_none() {
        (false, crate::NO_HMACS_PRESENT.to_string())
    } else if committed == 0 {
        (
            false,
            "the log holds no committed frame, so no frame's HMAC was checked".to_string(),
        )
    } else if failed_frames.is_empty() {
        (
            true,
            format!(
                "every one of the {committed} committed frame(s)' HMAC-SHA512 was recomputed over \
                 its ciphertext, initialisation vector and the page number the frame names, and \
                 matched the value stored in the frame"
            ),
        )
    } else {
        let listed: Vec<String> = failed_frames.iter().take(16).map(u32::to_string).collect();
        (
            false,
            format!(
                "{} of {committed} committed frame(s) failed HMAC verification: frame(s) {}. A \
                 frame whose HMAC does not match was altered, corrupted, or does not hold the \
                 page it names; its plaintext is still returned, and nothing recovered from it \
                 may be presented as sound",
                failed_frames.len(),
                listed.join(", ")
            ),
        )
    };
    let mut wal_statement = format!(
        "{committed} of {frames_in_file} frame(s) in the log belong to committed transactions in \
         its valid checksum chain and were decrypted; SQLite replays exactly these."
    );
    if not_committed > 0 {
        wal_statement.push_str(&format!(
            " {not_committed} frame(s) after the last valid commit (an uncommitted transaction, \
             or frames left from an earlier generation of the log) were not decrypted or \
             presented; what they hold is not established here."
        ));
    }
    if trailing_bytes > 0 {
        wal_statement.push_str(&format!(
            " {trailing_bytes} byte(s) at the end of the log do not make a whole frame and were \
             not read."
        ));
    }

    Some(WalDecryption {
        plaintext_wal: out,
        frames_in_file,
        frames_committed: committed,
        frames_not_committed: not_committed,
        integrity_verified,
        integrity_statement,
        failed_frames,
        wal_statement,
    })
}

/// Encrypt plaintext SQLite bytes into a SQLCipher 4 raw-key store — **for
/// tests only** (deterministic IVs). The plaintext's pages must already reserve
/// `cfg`'s per-page bytes (80 with HMAC). With a plaintext header, page 1's
/// first `plaintext_header_size` bytes are copied through; otherwise the salt
/// is written there, as SQLCipher does.
///
/// Exists so a consumer — the Signal parser's GRDB reader (HUNT-227) — can be
/// tested end to end on a store with real rows: the one real store held has
/// none. It is this project's own encryptor, so it proves agreement with this
/// crate's reader, not with SQLCipher; `tests/signal_ios_real_store.rs` is what
/// grades the reader against SQLCipher.
#[doc(hidden)]
pub fn encrypt_v4_raw_key_for_test(
    plain: &[u8],
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    cfg: &SqlCipher4Config,
) -> Vec<u8> {
    use cipher::BlockEncryptMut;
    let ps = cfg.page_size;
    let usable = ps - cfg.reserve();
    let masked: Vec<u8> = salt.iter().map(|b| b ^ HMAC_SALT_MASK).collect();
    let mut hmac_key = [0u8; 32];
    pbkdf2::pbkdf2::<HmacSha512>(key, &masked, FAST_KDF_ITER, &mut hmac_key);
    let header = if cfg.plaintext_header_size == 0 {
        SALT_LEN
    } else {
        cfg.plaintext_header_size
    };
    let mut out = Vec::with_capacity(plain.len());
    for (i, page) in plain.chunks_exact(ps).enumerate() {
        let page_number = i as u32 + 1;
        let off = if i == 0 { header } else { 0 };
        let mut page_out = vec![0u8; ps];
        if i == 0 {
            if cfg.plaintext_header_size == 0 {
                page_out[..SALT_LEN].copy_from_slice(salt);
            } else {
                page_out[..off].copy_from_slice(&page[..off]);
            }
        }
        let mut iv = [0x5au8; IV_LEN];
        iv[..4].copy_from_slice(&page_number.to_le_bytes());
        let mut ct = vec![0u8; usable - off];
        cbc::Encryptor::<Aes256>::new(key.into(), &iv.into())
            .encrypt_padded_b2b_mut::<NoPadding>(&page[off..usable], &mut ct)
            .expect("whole blocks");
        page_out[off..usable].copy_from_slice(&ct);
        page_out[usable..usable + IV_LEN].copy_from_slice(&iv);
        if cfg.use_hmac {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(&hmac_key).expect("any key length");
            mac.update(&page_out[off..usable + IV_LEN]);
            mac.update(&page_number.to_le_bytes());
            page_out[usable + IV_LEN..usable + IV_LEN + HMAC_SHA512_LEN]
                .copy_from_slice(&mac.finalize().into_bytes());
        }
        out.extend_from_slice(&page_out);
    }
    hmac_key.zeroize();
    out
}
