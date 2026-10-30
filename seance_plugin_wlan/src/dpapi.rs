//! Recognising a DPAPI protected blob, and reading the part of it that is
//! deliberately in the clear.
//!
//! # What this is for, and what it is not
//!
//! A Windows wireless profile's `keyMaterial` is either the passphrase in
//! plain text or a DPAPI blob. This establishes **which**, and where it is the
//! blob it reads the fields DPAPI leaves unencrypted — the master key's GUID
//! and the description — so a record can say what the field is and exactly
//! what recovering it would require.
//!
//! It does not decrypt, and it is not a step towards decrypting. Recovering a
//! machine-scope DPAPI secret needs the boot key from the SYSTEM hive, the
//! `DPAPI_SYSTEM` secret from the SECURITY hive, and the master-key file
//! `Windows\System32\Microsoft\Protect\S-1-5-18\User\{GUID}` (where LoneWolf's
//! is, `WLAN-1`) — three artefacts from
//! elsewhere in the image. Naming the GUID is what lets an examiner go and get
//! the third one. (`seance_plugin_clipboard::envelope` does the same for the
//! CNG blobs the clipboard uses, and for the same reason.)
//!
//! # The format
//!
//! `CryptProtectData` output, as documented by Microsoft and as every tool
//! that carves it reads it:
//!
//! ```text
//! DWORD  dwVersion                 always 1
//! GUID   guidProvider              df9d8cd0-1501-11d1-8c7a-00c04fc297eb
//! DWORD  dwMasterKeyVersion
//! GUID   guidMasterKey             the master-key file's name on disk
//! DWORD  dwFlags
//! DWORD  cbDescription  + UTF-16LE description
//! ALG_ID algCrypt + DWORD dwAlgCryptLen
//! DWORD  cbSalt + salt
//! DWORD  cbHmacKey + key
//! ALG_ID algHash + DWORD dwAlgHashLen
//! DWORD  cbHmac2Key + key
//! DWORD  cbData + ciphertext
//! DWORD  cbSign + signature
//! ```
//!
//! The provider GUID is the gate: the first twenty bytes of every such blob
//! are the version and that constant, which is why `01000000D08C9DDF…` at the
//! head of a hex string is the recognisable signature of one.

/// The one provider GUID `CryptProtectData` writes, as it appears on the wire:
/// the first three fields little-endian, the last eight in order. Documented
/// by Microsoft as `df9d8cd0-1501-11d1-8c7a-00c04fc297eb`.
const PROVIDER_GUID: [u8; 16] = [
    0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
];

/// Bytes of one blob this build will walk. A protected passphrase is a few
/// hundred; a field claiming megabytes is not one.
pub const MAX_BLOB_BYTES: usize = 64 * 1024;

/// Characters of a description read from a blob.
const MAX_DESCRIPTION_CHARS: usize = 512;

/// The parts of a DPAPI blob that are not encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub version: u32,
    pub master_key_version: u32,
    /// The master key this blob was encrypted under, in the form its file on
    /// disk is named — which is how an examiner finds that file.
    pub master_key_guid: String,
    /// The description DPAPI stores in the clear. Empty for a wireless key,
    /// which Windows protects without one; read anyway, because a blob that
    /// carries one is telling the examiner what it is.
    pub description: String,
    /// The whole blob, and the ciphertext inside it.
    pub blob_bytes: usize,
    pub ciphertext_bytes: usize,
}

impl Blob {
    /// What it would take to read this, which is the useful half of a record
    /// about something that cannot be read.
    pub fn statement(&self) -> String {
        format!(
            "The key is a DPAPI blob encrypted under the machine's master key {}. This build \
             does NOT decrypt it, and the passphrase is not in this record. Recovering it needs \
             three artefacts from elsewhere in the same image: the boot key from the SYSTEM \
             hive, the DPAPI_SYSTEM secret from the SECURITY hive, and the master-key file \
             Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\{} -- with those, the \
             blob above is decryptable by standard means.",
            self.master_key_guid, self.master_key_guid
        )
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": self.version,
            "master_key_version": self.master_key_version,
            "master_key_guid": self.master_key_guid,
            "description": self.description,
            "blob_bytes": self.blob_bytes,
            "ciphertext_bytes": self.ciphertext_bytes,
            "decrypted": false,
            "statement": self.statement(),
        })
    }
}

/// A hex string as bytes, or `None` where it is not one.
///
/// Windows writes `keyMaterial` as uppercase hex with nothing between the
/// bytes. Whitespace is tolerated because a document that has been through an
/// editor may carry it; anything else is not hex and is not guessed at.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) || cleaned.len() / 2 > MAX_BLOB_BYTES
    {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for pair in bytes.chunks(2) {
        let text = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(out)
}

/// Read a DPAPI blob's cleartext fields, or refuse it.
///
/// Refused rather than half-read: a blob whose declared lengths do not fit is
/// one whose fields are not where they are being read from, and a master key
/// GUID taken from the wrong offset would send an examiner to a file that does
/// not exist.
pub fn parse(bytes: &[u8]) -> Option<Blob> {
    if bytes.len() > MAX_BLOB_BYTES {
        return None;
    }
    let mut cursor = Cursor {
        bytes,
        at: 0,
        blob: bytes.len(),
    };
    let version = cursor.u32()?;
    // Version 1 is the only one CryptProtectData has ever written. A different
    // number is a different structure, and reading this one's offsets out of
    // it would be a guess.
    if version != 1 {
        return None;
    }
    if cursor.take(16)? != PROVIDER_GUID {
        return None;
    }
    let master_key_version = cursor.u32()?;
    let master_key_guid = guid(cursor.take(16)?)?;
    let _flags = cursor.u32()?;
    let description_bytes = cursor.u32()? as usize;
    let description = utf16(cursor.take(description_bytes)?);
    let _alg_crypt = cursor.u32()?;
    let _alg_crypt_len = cursor.u32()?;
    let salt = cursor.u32()? as usize;
    cursor.take(salt)?;
    let hmac_key = cursor.u32()? as usize;
    cursor.take(hmac_key)?;
    let _alg_hash = cursor.u32()?;
    let _alg_hash_len = cursor.u32()?;
    let hmac2_key = cursor.u32()? as usize;
    cursor.take(hmac2_key)?;
    let ciphertext_bytes = cursor.u32()? as usize;
    cursor.take(ciphertext_bytes)?;
    let signature = cursor.u32()? as usize;
    cursor.take(signature)?;
    Some(Blob {
        version,
        master_key_version,
        master_key_guid,
        description,
        blob_bytes: bytes.len(),
        ciphertext_bytes,
    })
}

/// Whether these bytes begin as a DPAPI blob. Cheaper than [`parse`] and used
/// to tell a protected key from a passphrase that happens to be hex.
pub fn looks_like_dpapi(bytes: &[u8]) -> bool {
    bytes.len() > 20 && bytes[0..4] == [1, 0, 0, 0] && bytes[4..20] == PROVIDER_GUID
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    blob: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        // A declared length larger than the whole blob is refused before it is
        // added to anything.
        if n > self.blob {
            return None;
        }
        let end = self.at.checked_add(n)?;
        let out = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// A GUID in the form Windows names its files by: the first three fields
/// little-endian, the last eight in order, lower case, no braces.
fn guid(bytes: &[u8]) -> Option<String> {
    let b: [u8; 16] = bytes.try_into().ok()?;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        b[3],
        b[2],
        b[1],
        b[0],
        b[5],
        b[4],
        b[7],
        b[6],
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    ))
}

/// A UTF-16LE string, lossily, with its trailing NUL dropped. Lossy because a
/// description with an unpaired surrogate is still evidence of a description.
fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .take(MAX_DESCRIPTION_CHARS)
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Fixtures shared by this module's tests and the profile parser's, so the
/// blob a profile test embeds is the same structure this module's own tests
/// grade against.
#[cfg(test)]
pub(crate) mod test_support {
    /// The provider GUID as Microsoft documents it, in text. Converted to the
    /// wire form by the same function the tests use for every other GUID, so
    /// the constant in the parser is checked against the documented value
    /// rather than against a copy of itself.
    pub const PROVIDER_TEXT: &str = "df9d8cd0-1501-11d1-8c7a-00c04fc297eb";

    /// The master key every fixture here is encrypted under.
    pub const MASTER_KEY: &str = "9c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8";

    /// A blob with the structure `CryptProtectData` writes, built field by
    /// field so every offset the parser reads from is one the test placed.
    pub fn blob(master_key: &str, description: &str, ciphertext: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&guid_bytes(PROVIDER_TEXT));
        out.extend_from_slice(&1u32.to_le_bytes()); // master key version
        out.extend_from_slice(&guid_bytes(master_key));
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        let mut utf16: Vec<u8> = description
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        utf16.extend_from_slice(&[0, 0]); // the trailing NUL Windows writes
        out.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        out.extend_from_slice(&utf16);
        out.extend_from_slice(&0x6610u32.to_le_bytes()); // algCrypt: CALG_AES_256
        out.extend_from_slice(&256u32.to_le_bytes());
        out.extend_from_slice(&16u32.to_le_bytes()); // salt
        out.extend_from_slice(&[0xaa; 16]);
        out.extend_from_slice(&0u32.to_le_bytes()); // hmac key
        out.extend_from_slice(&0x800eu32.to_le_bytes()); // algHash: CALG_SHA_512
        out.extend_from_slice(&512u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // hmac2 key
        out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(ciphertext);
        out.extend_from_slice(&64u32.to_le_bytes()); // signature
        out.extend_from_slice(&[0xbb; 64]);
        out
    }

    /// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` as Windows lays it out on disk.
    pub fn guid_bytes(text: &str) -> [u8; 16] {
        let hex: Vec<u8> = text
            .chars()
            .filter(|c| *c != '-')
            .collect::<String>()
            .as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&[hex[3], hex[2], hex[1], hex[0]]);
        out[4..6].copy_from_slice(&[hex[5], hex[4]]);
        out[6..8].copy_from_slice(&[hex[7], hex[6]]);
        out[8..16].copy_from_slice(&hex[8..16]);
        out
    }

    /// One whole blob, for a fixture that needs its hex.
    pub fn blob_for_tests() -> Vec<u8> {
        blob(MASTER_KEY, "", &[0x33; 48])
    }
}

#[cfg(test)]
#[path = "dpapi_tests.rs"]
mod dpapi_tests;
