//! WhatsApp Android `crypt14` and `crypt15` backup decryption, with a known
//! key.
//!
//! Written from public descriptions of the format, RFC 5869 (HKDF) and NIST
//! SP 800-38D (GCM), and confirmed only on real backups: the Pixel 7a crypt14
//! backups in `VALIDATION.md` `WHATSAPP-CRYPT14-1` and the published crypt15
//! backups in `WHATSAPP-CRYPT15-1`. No GPL tool's code is used. The layout:
//!
//! ```text
//! [n: u8][0x01, when the backup carries a feature list][protobuf, n bytes]
//! [AES-256-GCM ciphertext][GCM tag, 16][MD5 of all before, 16, where present]
//! ```
//!
//! - **crypt14**: the protobuf's field 2 holds the cipher parameters: cipher
//!   version (1), key version (2), the server salt (3), the Google ID (4) and
//!   the 16-byte IV (5). The key file (`/data/data/com.whatsapp/files/key`)
//!   is a Java-serialised `byte[]` of 131 bytes: cipher version (2), key
//!   version (1), server salt (32), Google ID (16), hashed Google ID (32), an
//!   IV (16) and the AES key (32). A key whose server salt is not the
//!   backup's is refused before any decryption is tried.
//! - **crypt15** (end-to-end encrypted backups): field 3 holds the IV (3.1),
//!   and there is no salt. The AES key is HKDF-SHA256 of the 32-byte root key
//!   (salt 32 zero bytes, info `backup encryption`). The root is what the
//!   phone shows as 64 hex digits, and what
//!   `/data/data/com.whatsapp/files/encrypted_backup.key` holds as a Java
//!   `byte[32]`. A multi-file backup (`stickers.backup.crypt15`) has no MD5
//!   trailer. A root derived from a password through WhatsApp's HSM is not
//!   something this module can obtain.
//!
//! The plaintext is a zlib stream or stored as it is, and holds an SQLite
//! database or a ZIP archive (a multi-file or incremental backup). The GCM tag
//! is checked before a byte of plaintext is released, so a wrong key or a
//! damaged file yields an error, never plausible-looking bytes.

/// The Java serialisation header of a `byte[]`, then its 4-byte length.
const JAVA_BYTE_ARRAY: [u8; 23] = [
    0xAC, 0xED, 0x00, 0x05, 0x75, 0x72, 0x00, 0x02, 0x5B, 0x42, 0xAC, 0xF3, 0x17, 0xF8, 0x06, 0x08,
    0x54, 0xE0, 0x02, 0x00, 0x00, 0x78, 0x70,
];

/// Length of the key file's payload.
const KEY_PAYLOAD: usize = 131;

/// Ceiling on the inflated database (the parser's own store cap).
pub const MAX_PLAINTEXT: u64 = 2 * 1024 * 1024 * 1024;

/// Why a backup was not decrypted.
#[derive(Debug, PartialEq, Eq)]
pub enum Crypt14Error {
    /// The file does not open with a `crypt14` header this module can read.
    NotCrypt14(String),
    /// The file is shorter than its header, tag and checksum.
    Truncated,
    /// The key file is not the 158-byte Java-serialised form.
    KeyFileUnreadable(String),
    /// The key's server salt is not the one the backup names: the backup was
    /// made under another key (an earlier install, another account).
    KeyMismatch,
    /// The GCM tag did not verify: wrong key, or the file is damaged.
    TagMismatch,
    /// The decrypted stream did not inflate.
    Inflate(String),
    /// The inflated stream is larger than [`MAX_PLAINTEXT`].
    TooLarge,
    /// The plaintext is neither an SQLite database nor a ZIP archive.
    NotSqlite,
    /// A crypt14 key file (it carries a server salt) offered to a crypt15
    /// backup, which opens only with the 64-digit end-to-end root key.
    Crypt14KeyOnCrypt15,
    /// The GCM tag verified, and the plaintext is a ZIP archive (a
    /// multi-file or incremental backup), which this build does not unpack.
    ZipPayload,
    /// A crypt15 root key (`encrypted_backup.key`) offered to a crypt14
    /// backup, which opens only with the install's `files/key`.
    Crypt15KeyOnCrypt14,
}

impl std::fmt::Display for Crypt14Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCrypt14(why) => write!(f, "not a crypt14 backup: {why}"),
            Self::Truncated => write!(f, "the file is shorter than its header, tag and checksum"),
            Self::KeyFileUnreadable(why) => write!(f, "the key file is unreadable: {why}"),
            Self::KeyMismatch => write!(
                f,
                "the key's server salt is not the backup's: it was made under another key"
            ),
            Self::TagMismatch => write!(
                f,
                "the GCM tag did not verify: the key is wrong or the file is damaged"
            ),
            Self::Inflate(why) => write!(f, "the decrypted stream did not inflate: {why}"),
            Self::TooLarge => write!(f, "the database inflates past {MAX_PLAINTEXT} bytes"),
            Self::NotSqlite => write!(
                f,
                "the decrypted stream is neither an SQLite database nor a ZIP archive"
            ),
            Self::Crypt14KeyOnCrypt15 => write!(
                f,
                "a crypt14 key file cannot open a crypt15 backup, which opens only with the \
                 64-digit end-to-end backup key"
            ),
            Self::ZipPayload => write!(
                f,
                "the GCM tag verified and the backup holds a ZIP archive (a multi-file or \
                 incremental backup), which this build does not unpack into messages"
            ),
            Self::Crypt15KeyOnCrypt14 => write!(
                f,
                "a crypt15 root key cannot open a crypt14 backup, which opens only with the \
                 key file `files/key` of the install that made it"
            ),
        }
    }
}

/// A WhatsApp key: the AES key, and the server salt when the key came from
/// the key file (a bare 32-byte key has none, and skips the salt check).
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    pub aes_key: [u8; 32],
    pub server_salt: Option<[u8; 32]>,
    pub google_id: Option<[u8; 16]>,
    pub key_version: Option<u8>,
    pub kind: KeyKind,
}

impl Drop for Key {
    // Held keys (the pairing holds them for hours) are zeroed when dropped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.aes_key.zeroize();
        if let Some(salt) = self.server_salt.as_mut() {
            salt.zeroize();
        }
    }
}

impl std::fmt::Debug for Key {
    // The key is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("server_salt", &self.server_salt.is_some())
            .field("key_version", &self.key_version)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// What a key was read as, which decides the backups it may open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// The crypt14 key file (`files/key`): an AES key and the server salt of
    /// the install that made it. Opens crypt14 only.
    Crypt14File,
    /// The crypt15 key file (`files/encrypted_backup.key`, a Java `byte[32]`):
    /// the end-to-end root key. Opens crypt15 only.
    Crypt15Root,
    /// 32 bare bytes (64 hex digits): a crypt14 AES key, or the 64-digit
    /// crypt15 root key the phone shows. Which one is decided by the backup's
    /// header, and the GCM tag decides whether it was right.
    Bare,
}

/// What a backup held once its GCM tag verified.
#[derive(Debug, PartialEq, Eq)]
pub enum Payload {
    /// An SQLite database (a message store, `wa.db`, ...).
    Database(Vec<u8>),
    /// A ZIP archive: a multi-file backup (`stickers.backup.crypt15`, stored
    /// raw) or an incremental one (zlib-wrapped).
    Archive(Vec<u8>),
}

/// A backup whose GCM tag verified, with whatever it held.
#[derive(Debug)]
pub struct Opened {
    pub header: Header,
    pub payload: Payload,
    /// Whether the plaintext was a zlib stream that was inflated.
    pub inflated: bool,
    /// Whether the file ends in an MD5 of everything before it (a multi-file
    /// crypt15 backup does not).
    pub checksum_present: bool,
    /// Whether that MD5 matches. `false` when there is none.
    pub checksum_ok: bool,
}

/// The crypt15 AES key: HKDF-SHA256 (RFC 5869) of the root key, with a salt
/// of 32 zero bytes and the info string `backup encryption`.
pub fn crypt15_aes_key(root: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    // Extract: PRK = HMAC(salt, IKM). Expand, one block: T1 = HMAC(PRK, info || 0x01).
    let mut extract = HmacSha256::new_from_slice(&[0u8; 32]).expect("any key length");
    extract.update(root);
    let prk = extract.finalize().into_bytes();
    let mut expand = HmacSha256::new_from_slice(&prk).expect("any key length");
    expand.update(b"backup encryption");
    expand.update(&[0x01]);
    expand.finalize().into_bytes().into()
}

/// Decrypt a crypt14 or crypt15 backup with `key` and return what it holds:
/// a database or a ZIP archive.
pub fn decrypt_backup(file: &[u8], key: &Key) -> Result<Opened, Crypt14Error> {
    let header = parse_header(file)?;
    let aes_key = zeroize::Zeroizing::new(match (header.generation, key.kind) {
        (15, KeyKind::Crypt14File) => return Err(Crypt14Error::Crypt14KeyOnCrypt15),
        (15, _) => crypt15_aes_key(&key.aes_key),
        (_, KeyKind::Crypt15Root) => return Err(Crypt14Error::Crypt15KeyOnCrypt14),
        _ => key.aes_key,
    });
    // crypt14 always ends in tag + MD5; a crypt15 multi-file backup ends in
    // the tag alone. At least one byte of ciphertext either way.
    let trailer_min = if header.generation == 15 { 16 } else { 32 };
    if file.len() < header.ciphertext_offset + trailer_min + 1 {
        return Err(Crypt14Error::Truncated);
    }
    if let (Some(ours), Some(theirs)) = (key.server_salt, header.server_salt) {
        if ours != theirs {
            return Err(Crypt14Error::KeyMismatch);
        }
    }

    // Where the tag is: before a trailing MD5 when the last 16 bytes are the
    // MD5 of everything before them; otherwise the file may end in the tag
    // (a crypt15 with no MD5), or in an MD5 that does not match (damage the
    // tag cannot see, since the MD5 is outside it). Each reading is tried
    // only through the tag, so neither can release unauthenticated bytes.
    let md5_matches = file.len() >= header.ciphertext_offset + 33 && {
        let digest = seance_core::hashing::compute_hashes(&file[..file.len() - 16]).md5;
        let stored: String = file[file.len() - 16..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        digest == stored
    };
    let mut readings: Vec<(usize, bool, bool)> = Vec::new(); // (tag at, present, ok)
    if md5_matches {
        readings.push((file.len() - 32, true, true));
    } else {
        if header.generation == 15 {
            readings.push((file.len() - 16, false, false));
        }
        if file.len() >= header.ciphertext_offset + 33 {
            readings.push((file.len() - 32, true, false));
        }
    }
    let mut opened = None;
    for (tag_at, present, ok) in readings {
        let tag: [u8; 16] = file[tag_at..tag_at + 16].try_into().expect("16 bytes");
        if let Ok(plain) = crate::gcm::decrypt(
            &aes_key,
            &header.iv,
            &file[header.ciphertext_offset..tag_at],
            &tag,
        ) {
            opened = Some((plain, present, ok));
            break;
        }
    }
    let (plain, checksum_present, checksum_ok) = opened.ok_or(Crypt14Error::TagMismatch)?;
    let (payload, inflated) = classify(plain)?;
    Ok(Opened {
        header,
        payload,
        inflated,
        checksum_present,
        checksum_ok,
    })
}

/// A zlib stream header (RFC 1950): deflate, and the check bits.
fn is_zlib(b: &[u8]) -> bool {
    b.len() >= 2 && b[0] & 0x0F == 8 && (u16::from(b[0]) << 8 | u16::from(b[1])) % 31 == 0
}

/// Inflate the plaintext where it is a zlib stream, and say what it holds.
fn classify(plain: Vec<u8>) -> Result<(Payload, bool), Crypt14Error> {
    let (bytes, inflated) = if is_zlib(&plain) {
        let mut out = Vec::new();
        let mut z = flate2::read::ZlibDecoder::new(&plain[..]);
        use std::io::Read;
        let read = (&mut z)
            .take(MAX_PLAINTEXT + 1)
            .read_to_end(&mut out)
            .map_err(|e| Crypt14Error::Inflate(e.to_string()))?;
        if read as u64 > MAX_PLAINTEXT {
            return Err(Crypt14Error::TooLarge);
        }
        (out, true)
    } else {
        (plain, false)
    };
    if bytes.starts_with(b"SQLite format 3\0") {
        Ok((Payload::Database(bytes), inflated))
    } else if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        Ok((Payload::Archive(bytes), inflated))
    } else {
        Err(Crypt14Error::NotSqlite)
    }
}

/// The parameters a `crypt14` header carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Where the ciphertext starts.
    pub ciphertext_offset: usize,
    pub iv: [u8; 16],
    pub server_salt: Option<[u8; 32]>,
    pub google_id: Option<[u8; 16]>,
    pub key_version: Option<Vec<u8>>,
    /// The WhatsApp version string the backup records, where it does.
    pub app_version: Option<String>,
    /// Whether the `0x01` feature-list byte follows the length byte.
    pub has_feature_flag: bool,
    /// 14 or 15: which scheme the header describes.
    pub generation: u32,
}

/// A decrypted backup.
#[derive(Debug)]
pub struct Decrypted {
    pub header: Header,
    /// The SQLite database.
    pub database: Vec<u8>,
    /// Whether the trailing MD5 matches the file (the GCM tag already
    /// authenticated the ciphertext; this is the file's own checksum).
    pub checksum_ok: bool,
}

/// Read the key file (`files/key`) or a bare 32-byte key.
pub fn parse_key(bytes: &[u8]) -> Result<Key, Crypt14Error> {
    if bytes.len() == 32 {
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(bytes);
        return Ok(Key {
            aes_key,
            server_salt: None,
            google_id: None,
            key_version: None,
            kind: KeyKind::Bare,
        });
    }
    let unreadable = |why: &str| Crypt14Error::KeyFileUnreadable(why.to_string());
    // `files/encrypted_backup.key`: a Java `byte[32]`, the crypt15 root key.
    if bytes.len() == JAVA_BYTE_ARRAY.len() + 4 + 32
        && bytes[..JAVA_BYTE_ARRAY.len()] == JAVA_BYTE_ARRAY
        && bytes[JAVA_BYTE_ARRAY.len()..JAVA_BYTE_ARRAY.len() + 4] == 32u32.to_be_bytes()
    {
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&bytes[JAVA_BYTE_ARRAY.len() + 4..]);
        return Ok(Key {
            aes_key,
            server_salt: None,
            google_id: None,
            key_version: None,
            kind: KeyKind::Crypt15Root,
        });
    }
    if bytes.len() != JAVA_BYTE_ARRAY.len() + 4 + KEY_PAYLOAD {
        return Err(unreadable(
            "neither 158 bytes (the crypt14 `key`, a Java byte[] of 131) nor 59 (the crypt15 \
             `encrypted_backup.key`, a Java byte[] of 32)",
        ));
    }
    if bytes[..JAVA_BYTE_ARRAY.len()] != JAVA_BYTE_ARRAY {
        return Err(unreadable("no Java byte[] serialisation header"));
    }
    let n = JAVA_BYTE_ARRAY.len();
    if u32::from_be_bytes([bytes[n], bytes[n + 1], bytes[n + 2], bytes[n + 3]]) as usize
        != KEY_PAYLOAD
    {
        return Err(unreadable("the array is not 131 bytes long"));
    }
    let p = &bytes[n + 4..];
    let mut server_salt = [0u8; 32];
    server_salt.copy_from_slice(&p[3..35]);
    let mut google_id = [0u8; 16];
    google_id.copy_from_slice(&p[35..51]);
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&p[KEY_PAYLOAD - 32..]);
    Ok(Key {
        aes_key,
        server_salt: Some(server_salt),
        google_id: Some(google_id),
        key_version: Some(p[2]),
        kind: KeyKind::Crypt14File,
    })
}

/// A protobuf varint at `*at`, advancing past it.
fn varint(buf: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*at)?;
        *at += 1;
        v |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The fields of one protobuf message: (field number, wire type, payload).
/// Varints come back as their bytes' value in `u64`, length-delimited fields
/// as their bytes. `None` for anything that does not parse to the end.
/// One protobuf field: (field number, wire type, value or length, payload).
type Field<'a> = (u64, u8, u64, &'a [u8]);

fn fields(buf: &[u8]) -> Option<Vec<Field<'_>>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let tag = varint(buf, &mut at)?;
        let (field, wire) = (tag >> 3, (tag & 7) as u8);
        if field == 0 {
            return None;
        }
        match wire {
            0 => out.push((field, 0, varint(buf, &mut at)?, &buf[0..0])),
            2 => {
                let len = varint(buf, &mut at)? as usize;
                let data = buf.get(at..at.checked_add(len)?)?;
                at += len;
                out.push((field, 2, len as u64, data));
            }
            1 => {
                at = at.checked_add(8).filter(|&a| a <= buf.len())?;
                out.push((field, 1, 0, &buf[0..0]));
            }
            5 => {
                at = at.checked_add(4).filter(|&a| a <= buf.len())?;
                out.push((field, 5, 0, &buf[0..0]));
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Read a `crypt14` header.
pub fn parse_header(file: &[u8]) -> Result<Header, Crypt14Error> {
    let not = |why: &str| Crypt14Error::NotCrypt14(why.to_string());
    let n = *file.first().ok_or_else(|| not("empty"))? as usize;
    // A protobuf never opens with 0x01 (field 0), so that byte is the flag.
    let has_feature_flag = file.get(1) == Some(&0x01);
    let start = if has_feature_flag { 2 } else { 1 };
    let proto = file
        .get(start..start + n)
        .ok_or_else(|| not("shorter than its header"))?;
    let top = fields(proto).ok_or_else(|| not("the header is not a protobuf message"))?;
    let app_version = top
        .iter()
        .find(|(f, w, _, _)| *f == 4 && *w == 2)
        .and_then(|(_, _, _, d)| fields(d))
        .and_then(|info| {
            info.iter()
                .find(|(f, w, _, _)| *f == 1 && *w == 2)
                .and_then(|(_, _, _, d)| std::str::from_utf8(d).ok().map(str::to_string))
        });
    // crypt15: field 3 holds the IV (3.1); there is no server salt, since the
    // key is derived from the end-to-end root key alone.
    if let Some((_, _, _, c15)) = top.iter().find(|(f, w, _, _)| *f == 3 && *w == 2) {
        let iv: [u8; 16] = fields(c15)
            .and_then(|f| {
                f.iter()
                    .find(|(f, w, _, _)| *f == 1 && *w == 2)
                    .and_then(|(_, _, _, d)| (*d).try_into().ok())
            })
            .ok_or_else(|| not("no 16-byte crypt15 IV (field 3.1)"))?;
        return Ok(Header {
            ciphertext_offset: start + n,
            iv,
            server_salt: None,
            google_id: None,
            key_version: None,
            app_version,
            has_feature_flag,
            generation: 15,
        });
    }
    let cipher = top
        .iter()
        .find(|(f, w, _, _)| *f == 2 && *w == 2)
        .map(|(_, _, _, d)| *d)
        .ok_or_else(|| not("no cipher parameters (field 2)"))?;
    let cipher = fields(cipher).ok_or_else(|| not("the cipher parameters do not parse"))?;
    let bytes_of = |field: u64| {
        cipher
            .iter()
            .find(|(f, w, _, _)| *f == field && *w == 2)
            .map(|(_, _, _, d)| *d)
    };
    let iv: [u8; 16] = bytes_of(5)
        .and_then(|d| d.try_into().ok())
        .ok_or_else(|| not("no 16-byte IV (field 2.5)"))?;
    Ok(Header {
        ciphertext_offset: start + n,
        iv,
        server_salt: bytes_of(3).and_then(|d| d.try_into().ok()),
        google_id: bytes_of(4).and_then(|d| d.try_into().ok()),
        key_version: bytes_of(2).map(<[u8]>::to_vec),
        app_version,
        has_feature_flag,
        generation: 14,
    })
}

/// Decrypt a `crypt14` or `crypt15` backup that holds a database. A backup
/// that holds a ZIP archive is refused as [`Crypt14Error::ZipPayload`] after
/// its tag verified; [`decrypt_backup`] returns either.
pub fn decrypt(file: &[u8], key: &Key) -> Result<Decrypted, Crypt14Error> {
    let opened = decrypt_backup(file, key)?;
    match opened.payload {
        Payload::Database(database) => Ok(Decrypted {
            header: opened.header,
            database,
            checksum_ok: opened.checksum_ok,
        }),
        Payload::Archive(_) => Err(Crypt14Error::ZipPayload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &[u8] = include_bytes!("../tests/fixtures/synthetic.crypt14");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/synthetic.key");
    const DB: &[u8] = include_bytes!("../tests/fixtures/synthetic.db");

    #[test]
    fn the_synthetic_backup_decrypts_to_its_database() {
        let key = parse_key(KEY).expect("key file");
        assert_eq!(key.aes_key, std::array::from_fn(|i| 0x40 + i as u8));
        assert_eq!(
            key.server_salt,
            Some(std::array::from_fn(|i| 0x10 + i as u8))
        );
        let d = decrypt(FILE, &key).expect("decrypts");
        assert_eq!(d.database, DB);
        assert!(d.checksum_ok);
        assert!(d.header.has_feature_flag);
        assert_eq!(d.header.iv, std::array::from_fn(|i| 0x70 + i as u8));
    }

    #[test]
    fn crypt14_rejects_wrong_key_by_gcm_tag() {
        let mut key = parse_key(KEY).unwrap();
        key.aes_key[7] ^= 1;
        assert_eq!(decrypt(FILE, &key).unwrap_err(), Crypt14Error::TagMismatch);
        // A bare key skips the salt check and is refused by the tag alone.
        let mut bare = [0u8; 32];
        bare.copy_from_slice(&KEY[KEY.len() - 32..]);
        bare[0] ^= 1;
        let bare = parse_key(&bare).unwrap();
        assert_eq!(bare.server_salt, None);
        assert_eq!(decrypt(FILE, &bare).unwrap_err(), Crypt14Error::TagMismatch);
    }

    #[test]
    fn a_key_made_for_another_backup_is_refused_before_decryption() {
        let mut key = parse_key(KEY).unwrap();
        key.server_salt.as_mut().unwrap()[0] ^= 1;
        assert_eq!(decrypt(FILE, &key).unwrap_err(), Crypt14Error::KeyMismatch);
    }

    #[test]
    fn a_flipped_ciphertext_byte_is_refused() {
        let key = parse_key(KEY).unwrap();
        let mut bad = FILE.to_vec();
        let at = parse_header(FILE).unwrap().ciphertext_offset + 3;
        bad[at] ^= 0x20;
        assert_eq!(decrypt(&bad, &key).unwrap_err(), Crypt14Error::TagMismatch);
    }

    #[test]
    fn crypt14_rejects_truncated_file() {
        let key = parse_key(KEY).unwrap();
        for len in [0, 1, 2, 40, 90, FILE.len() - 33, FILE.len() - 1] {
            assert!(decrypt(&FILE[..len], &key).is_err(), "length {len}");
        }
        assert_eq!(
            decrypt(
                &FILE[..parse_header(FILE).unwrap().ciphertext_offset + 20],
                &key
            )
            .unwrap_err(),
            Crypt14Error::Truncated
        );
    }

    #[test]
    fn a_crypt15_header_is_read_as_generation_15() {
        // Field 3 (the crypt15 IV) where crypt14 has field 2.
        let mut c15 = vec![0u8, 0x01, 0x08, 0x01, 0x1A, 0x12, 0x0A, 0x10];
        c15.extend_from_slice(&[0x55; 16]);
        c15[0] = (c15.len() - 2) as u8;
        c15.extend_from_slice(&[0u8; 64]);
        let h = parse_header(&c15).expect("a crypt15 header");
        assert_eq!(h.generation, 15);
        assert_eq!(h.iv, [0x55; 16]);
        assert_eq!(h.server_salt, None);
    }

    #[test]
    fn a_key_file_of_the_wrong_shape_is_refused() {
        assert!(matches!(
            parse_key(&KEY[..157]),
            Err(Crypt14Error::KeyFileUnreadable(_))
        ));
        let mut bad = KEY.to_vec();
        bad[0] = 0;
        assert!(matches!(
            parse_key(&bad),
            Err(Crypt14Error::KeyFileUnreadable(_))
        ));
    }

    #[test]
    fn random_bytes_are_not_a_crypt14_header() {
        assert!(matches!(
            parse_header(b"SQLite format 3\0 and so on and so forth"),
            Err(Crypt14Error::NotCrypt14(_))
        ));
    }

    // ---- crypt15 (ROADMAP §5.7). Synthetic fixtures made by
    // tests/fixtures/make_synthetic_crypt15.py with Python's `cryptography`
    // (OpenSSL): they pin the mechanism; the real backups in
    // tests/real_crypt15.rs grade it.
    const C15_KEY: &[u8] = include_bytes!("../tests/fixtures/synthetic_encrypted_backup.key");
    const C15_STORE: &[u8] = include_bytes!("../tests/fixtures/synthetic_msgstore.db.crypt15");
    const C15_NOFEATURE: &[u8] = include_bytes!("../tests/fixtures/synthetic_nofeature.db.crypt15");
    const C15_STICKERS: &[u8] =
        include_bytes!("../tests/fixtures/synthetic_stickers.backup.crypt15");
    const C15_INCREMENT: &[u8] = include_bytes!("../tests/fixtures/synthetic_increment.crypt15");
    const C15_DB: &[u8] = include_bytes!("../tests/fixtures/synthetic_crypt15_msgstore.db");
    const C15_ZIP: &[u8] = include_bytes!("../tests/fixtures/synthetic_crypt15_archive.zip");

    fn c15_root() -> [u8; 32] {
        std::array::from_fn(|i| 0x90 + i as u8)
    }

    #[test]
    fn the_crypt15_key_is_hkdf_sha256_of_the_root() {
        // RFC 5869 test case 3 has an empty salt and info; this is the
        // WhatsApp shape (32 zero bytes of salt, info "backup encryption"),
        // checked against Python's `cryptography` HKDF on the synthetic root.
        let k = crypt15_aes_key(&c15_root());
        let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "d1ada23b88db2284540e8d3b440806c388018d869f35f22f755c5eb50bdc65f2"
        );
    }

    #[test]
    fn a_java_byte32_is_read_as_the_crypt15_root_key() {
        let key = parse_key(C15_KEY).expect("a Java byte[32]");
        assert_eq!(key.kind, KeyKind::Crypt15Root);
        assert_eq!(key.aes_key, c15_root());
        assert_eq!(key.server_salt, None);
    }

    #[test]
    fn a_crypt15_store_decrypts_and_inflates_to_its_database() {
        let key = parse_key(C15_KEY).unwrap();
        let o = decrypt_backup(C15_STORE, &key).expect("decrypts");
        assert_eq!(o.header.generation, 15);
        assert!(o.header.has_feature_flag);
        assert_eq!(o.header.iv, std::array::from_fn(|i| 0xC0 + i as u8));
        assert_eq!(o.header.app_version.as_deref(), Some("2.99.1.1"));
        assert!(o.inflated && o.checksum_present && o.checksum_ok);
        assert_eq!(o.payload, Payload::Database(C15_DB.to_vec()));
        // The database path gives the same bytes.
        assert_eq!(decrypt(C15_STORE, &key).unwrap().database, C15_DB);
        // As does the root typed as 64 hex digits (32 bare bytes).
        let bare = parse_key(&c15_root()).unwrap();
        assert_eq!(bare.kind, KeyKind::Bare);
        assert_eq!(decrypt(C15_STORE, &bare).unwrap().database, C15_DB);
    }

    #[test]
    fn a_crypt15_header_without_the_feature_byte_is_read() {
        let key = parse_key(C15_KEY).unwrap();
        let o = decrypt_backup(C15_NOFEATURE, &key).expect("decrypts");
        assert!(!o.header.has_feature_flag);
        assert_eq!(o.payload, Payload::Database(C15_DB.to_vec()));
    }

    #[test]
    fn a_raw_zip_with_no_md5_trailer_decrypts_to_the_archive() {
        let key = parse_key(C15_KEY).unwrap();
        let o = decrypt_backup(C15_STICKERS, &key).expect("decrypts");
        assert!(!o.inflated);
        assert!(!o.checksum_present && !o.checksum_ok);
        assert_eq!(o.payload, Payload::Archive(C15_ZIP.to_vec()));
        // The database path refuses it by name.
        assert_eq!(
            decrypt(C15_STICKERS, &key).unwrap_err(),
            Crypt14Error::ZipPayload
        );
    }

    #[test]
    fn a_zlib_wrapped_zip_with_an_md5_trailer_decrypts_to_the_archive() {
        let key = parse_key(C15_KEY).unwrap();
        let o = decrypt_backup(C15_INCREMENT, &key).expect("decrypts");
        assert!(o.inflated && o.checksum_present && o.checksum_ok);
        assert_eq!(o.payload, Payload::Archive(C15_ZIP.to_vec()));
    }

    #[test]
    fn a_wrong_root_or_a_damaged_crypt15_is_refused_by_the_tag() {
        let mut wrong = c15_root();
        wrong[0] ^= 1;
        let wrong = parse_key(&wrong).unwrap();
        for file in [C15_STORE, C15_NOFEATURE, C15_STICKERS, C15_INCREMENT] {
            assert_eq!(
                decrypt_backup(file, &wrong).unwrap_err(),
                Crypt14Error::TagMismatch
            );
        }
        let key = parse_key(C15_KEY).unwrap();
        for file in [C15_STORE, C15_STICKERS] {
            let mut bad = file.to_vec();
            let at = parse_header(file).unwrap().ciphertext_offset + 2;
            bad[at] ^= 0x10;
            assert_eq!(
                decrypt_backup(&bad, &key).unwrap_err(),
                Crypt14Error::TagMismatch
            );
        }
    }

    #[test]
    fn a_damaged_md5_trailer_is_reported_not_hidden() {
        let key = parse_key(C15_KEY).unwrap();
        let mut bad = C15_STORE.to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let o = decrypt_backup(&bad, &key).expect("the tag still verifies");
        assert!(o.checksum_present, "the tag sits before a 16-byte trailer");
        assert!(!o.checksum_ok);
    }

    #[test]
    fn keys_are_refused_on_the_other_generation_by_name() {
        let c14 = parse_key(KEY).unwrap();
        assert_eq!(
            decrypt_backup(C15_STORE, &c14).unwrap_err(),
            Crypt14Error::Crypt14KeyOnCrypt15
        );
        let c15 = parse_key(C15_KEY).unwrap();
        assert_eq!(
            decrypt_backup(FILE, &c15).unwrap_err(),
            Crypt14Error::Crypt15KeyOnCrypt14
        );
    }

    #[test]
    fn crypt15_rejects_truncated_file() {
        let key = parse_key(C15_KEY).unwrap();
        for file in [C15_STORE, C15_STICKERS] {
            for len in [0, 1, 2, 40, file.len() - 17, file.len() - 1] {
                assert!(decrypt_backup(&file[..len], &key).is_err(), "length {len}");
            }
        }
    }
}
