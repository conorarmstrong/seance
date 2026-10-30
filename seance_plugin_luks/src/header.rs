//! On-disk LUKS header parsing (LUKS1 binary phdr and LUKS2 JSON metadata).
//!
//! All LUKS1 multi-byte integers are big-endian. LUKS2 keeps a 4096-byte binary
//! header followed by a NUL-padded JSON metadata area; the numeric JSON fields
//! (offsets, sizes) are encoded as decimal strings to stay 64-bit safe.

use crate::error::LuksError;
use seance_core::data_source::DataSource;
use seance_core::io::read_exact_or_fail;
use serde::Deserialize;
use std::collections::BTreeMap;

/// LUKS magic: "LUKS" followed by 0xBA 0xBE.
pub const LUKS_MAGIC: [u8; 6] = [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE];

pub const LUKS1_NUMKEYS: usize = 8;
pub const LUKS1_DIGEST_SIZE: usize = 20;
pub const LUKS1_SALT_SIZE: usize = 32;
/// Keyslot `active` marker for an enabled LUKS1 keyslot.
pub const LUKS1_KEY_ENABLED: u32 = 0x00AC_71F3;
/// Sector size used by LUKS1 payload/keyslot addressing.
pub const SECTOR: u64 = 512;

/// LUKS2 binary header length in bytes; the JSON area follows it.
const LUKS2_BIN_HDR_LEN: u64 = 4096;
/// Defensive cap on the JSON metadata area we will read.
const LUKS2_MAX_JSON: u64 = 16 * 1024 * 1024;

/// A parsed LUKS header, either format.
#[derive(Debug)]
pub enum LuksHeader {
    V1(Box<Luks1Header>),
    V2(Box<Luks2Header>),
}

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Trim a fixed-width, NUL-padded C string field to a Rust `String`.
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Check whether a volume begins with the LUKS magic.
pub fn has_luks_magic(vol: &dyn DataSource) -> bool {
    let mut buf = [0u8; 6];
    read_exact_or_fail(vol, 0, &mut buf, "LUKS magic").is_ok() && buf == LUKS_MAGIC
}

/// Parse whichever LUKS header version the volume carries.
pub fn parse(vol: &dyn DataSource) -> Result<LuksHeader, LuksError> {
    let mut head = [0u8; 8];
    read_exact_or_fail(vol, 0, &mut head, "LUKS magic and version")?;
    if head[..6] != LUKS_MAGIC {
        return Err(LuksError::NotLuks);
    }
    match be_u16(&head[6..8]) {
        1 => Ok(LuksHeader::V1(Box::new(parse_luks1(vol)?))),
        2 => Ok(LuksHeader::V2(Box::new(parse_luks2(vol)?))),
        v => Err(LuksError::UnsupportedVersion(v)),
    }
}

// ---------------------------------------------------------------------------
// LUKS1
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Luks1Keyslot {
    pub active: bool,
    pub iterations: u32,
    pub salt: [u8; LUKS1_SALT_SIZE],
    pub key_material_offset_sectors: u32,
    pub stripes: u32,
}

#[derive(Debug, Clone)]
pub struct Luks1Header {
    pub cipher_name: String,
    pub cipher_mode: String,
    pub hash_spec: String,
    pub payload_offset_sectors: u32,
    pub key_bytes: u32,
    pub mk_digest: [u8; LUKS1_DIGEST_SIZE],
    pub mk_digest_salt: [u8; LUKS1_SALT_SIZE],
    pub mk_digest_iterations: u32,
    pub uuid: String,
    pub keyslots: Vec<Luks1Keyslot>,
}

/// LUKS1 phdr is 208 bytes of fixed fields + 8 * 48-byte keyslots = 592 bytes.
fn parse_luks1(vol: &dyn DataSource) -> Result<Luks1Header, LuksError> {
    let mut hdr = [0u8; 592];
    read_exact_or_fail(vol, 0, &mut hdr, "LUKS1 phdr")?;

    let cipher_name = cstr(&hdr[8..40]);
    let cipher_mode = cstr(&hdr[40..72]);
    let hash_spec = cstr(&hdr[72..104]);
    let payload_offset_sectors = be_u32(&hdr[104..108]);
    let key_bytes = be_u32(&hdr[108..112]);

    let mut mk_digest = [0u8; LUKS1_DIGEST_SIZE];
    mk_digest.copy_from_slice(&hdr[112..132]);
    let mut mk_digest_salt = [0u8; LUKS1_SALT_SIZE];
    mk_digest_salt.copy_from_slice(&hdr[132..164]);
    let mk_digest_iterations = be_u32(&hdr[164..168]);
    let uuid = cstr(&hdr[168..208]);

    if key_bytes == 0 || key_bytes > 1024 {
        return Err(LuksError::Malformed(format!(
            "implausible key_bytes {key_bytes}"
        )));
    }

    let mut keyslots = Vec::with_capacity(LUKS1_NUMKEYS);
    for i in 0..LUKS1_NUMKEYS {
        let base = 208 + i * 48;
        let active_raw = be_u32(&hdr[base..base + 4]);
        let iterations = be_u32(&hdr[base + 4..base + 8]);
        let mut salt = [0u8; LUKS1_SALT_SIZE];
        salt.copy_from_slice(&hdr[base + 8..base + 40]);
        let key_material_offset_sectors = be_u32(&hdr[base + 40..base + 44]);
        let stripes = be_u32(&hdr[base + 44..base + 48]);
        keyslots.push(Luks1Keyslot {
            active: active_raw == LUKS1_KEY_ENABLED,
            iterations,
            salt,
            key_material_offset_sectors,
            stripes,
        });
    }

    Ok(Luks1Header {
        cipher_name,
        cipher_mode,
        hash_spec,
        payload_offset_sectors,
        key_bytes,
        mk_digest,
        mk_digest_salt,
        mk_digest_iterations,
        uuid,
        keyslots,
    })
}

// ---------------------------------------------------------------------------
// LUKS2
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Luks2Header {
    pub hdr_size: u64,
    pub meta: Luks2Metadata,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Metadata {
    #[serde(default)]
    pub keyslots: BTreeMap<String, Luks2Keyslot>,
    #[serde(default)]
    pub segments: BTreeMap<String, Luks2Segment>,
    #[serde(default)]
    pub digests: BTreeMap<String, Luks2Digest>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Keyslot {
    #[serde(rename = "type")]
    pub kind: String,
    pub key_size: usize,
    pub af: Luks2Af,
    pub area: Luks2Area,
    pub kdf: Luks2Kdf,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Af {
    #[serde(rename = "type")]
    pub kind: String,
    pub stripes: usize,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Area {
    #[serde(rename = "type")]
    pub kind: String,
    pub offset: String,
    pub size: String,
    pub encryption: String,
    pub key_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Kdf {
    #[serde(rename = "type")]
    pub kind: String,
    pub salt: String,
    // pbkdf2 fields
    pub hash: Option<String>,
    pub iterations: Option<u32>,
    // argon2 fields
    pub time: Option<u32>,
    pub memory: Option<u32>,
    pub cpus: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Segment {
    #[serde(rename = "type")]
    pub kind: String,
    pub offset: String,
    pub size: String,
    #[serde(default)]
    pub iv_tweak: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub sector_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct Luks2Digest {
    #[serde(rename = "type")]
    pub kind: String,
    pub keyslots: Vec<String>,
    #[serde(default)]
    pub segments: Vec<String>,
    pub hash: String,
    pub iterations: u32,
    pub salt: String,
    pub digest: String,
}

fn parse_luks2(vol: &dyn DataSource) -> Result<Luks2Header, LuksError> {
    // Binary header: magic(6) version(2) hdr_size(8, big-endian) ...
    let mut bin = [0u8; 64];
    read_exact_or_fail(vol, 0, &mut bin, "LUKS2 binary header")?;
    let hdr_size = be_u64(&bin[8..16]);
    if hdr_size <= LUKS2_BIN_HDR_LEN || hdr_size > LUKS2_BIN_HDR_LEN + LUKS2_MAX_JSON {
        return Err(LuksError::Malformed(format!(
            "implausible hdr_size {hdr_size}"
        )));
    }

    let json_len = (hdr_size - LUKS2_BIN_HDR_LEN) as usize;
    let mut json_bytes = vec![0u8; json_len];
    read_exact_or_fail(
        vol,
        LUKS2_BIN_HDR_LEN,
        &mut json_bytes,
        "LUKS2 JSON metadata area",
    )?;
    // The JSON string is NUL-padded to fill the area.
    let end = json_bytes
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(json_bytes.len());
    let json_str = std::str::from_utf8(&json_bytes[..end])
        .map_err(|e| LuksError::Metadata(format!("JSON not UTF-8: {e}")))?;

    let meta: Luks2Metadata =
        serde_json::from_str(json_str).map_err(|e| LuksError::Metadata(e.to_string()))?;

    Ok(Luks2Header { hdr_size, meta })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    use seance_core::test_support::DribbleSource;

    /// Build a 592-byte LUKS1 phdr with one active keyslot.
    fn luks1_header() -> Vec<u8> {
        let mut h = vec![0u8; 592];
        h[..6].copy_from_slice(&LUKS_MAGIC);
        h[6..8].copy_from_slice(&1u16.to_be_bytes());
        h[8..11].copy_from_slice(b"aes");
        h[40..51].copy_from_slice(b"xts-plain64");
        h[72..78].copy_from_slice(b"sha256");
        h[104..108].copy_from_slice(&8u32.to_be_bytes());
        h[108..112].copy_from_slice(&64u32.to_be_bytes());
        h[164..168].copy_from_slice(&1000u32.to_be_bytes());
        h[208..212].copy_from_slice(&LUKS1_KEY_ENABLED.to_be_bytes());
        h[212..216].copy_from_slice(&2000u32.to_be_bytes());
        h[248..252].copy_from_slice(&2u32.to_be_bytes());
        h[252..256].copy_from_slice(&4000u32.to_be_bytes());
        h
    }

    #[test]
    fn parses_luks1_from_a_short_reading_source() {
        // The header read must loop: a volume that dribbles 64 bytes per call
        // still carries a complete, valid phdr.
        let src = DribbleSource::new(luks1_header(), 64);
        assert!(has_luks_magic(&src));
        match parse(&src).expect("a chunked source must still parse") {
            LuksHeader::V1(hd) => assert_eq!(hd.key_bytes, 64),
            _ => panic!("expected LUKS1"),
        }
    }

    #[test]
    fn truncated_luks1_header_errors_instead_of_zero_padding() {
        // Only half the phdr exists. Parsing the zero-padded remainder would
        // invent keyslot geometry, so the read must fail closed.
        let mut short = luks1_header();
        short.truncate(300);
        let src = ByteSliceDataSource::new(short);
        assert!(matches!(parse(&src), Err(LuksError::Io(_))));
    }

    #[test]
    fn rejects_non_luks() {
        let src = ByteSliceDataSource::new(vec![0u8; 4096]);
        assert!(matches!(parse(&src), Err(LuksError::NotLuks)));
        assert!(!has_luks_magic(&src));
    }

    #[test]
    fn parses_minimal_luks1_fields() {
        let src = ByteSliceDataSource::new(luks1_header());
        match parse(&src).unwrap() {
            LuksHeader::V1(hd) => {
                assert_eq!(hd.cipher_name, "aes");
                assert_eq!(hd.cipher_mode, "xts-plain64");
                assert_eq!(hd.hash_spec, "sha256");
                assert_eq!(hd.payload_offset_sectors, 8);
                assert_eq!(hd.key_bytes, 64);
                assert!(hd.keyslots[0].active);
                assert_eq!(hd.keyslots[0].iterations, 2000);
                assert_eq!(hd.keyslots[0].stripes, 4000);
                assert!(!hd.keyslots[1].active);
            }
            _ => panic!("expected LUKS1"),
        }
    }

    #[test]
    fn parses_luks2_json() {
        let json = r#"{
            "keyslots": {"0": {"type":"luks2","key_size":64,
                "af":{"type":"luks1","stripes":4000,"hash":"sha256"},
                "area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},
                "kdf":{"type":"pbkdf2","salt":"AAAA","hash":"sha256","iterations":1000}}},
            "segments": {"0": {"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}},
            "digests": {"0": {"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":2000,"salt":"BBBB","digest":"CCCC"}}
        }"#;
        let mut buf = vec![0u8; 4096];
        buf[..6].copy_from_slice(&LUKS_MAGIC);
        buf[6..8].copy_from_slice(&2u16.to_be_bytes());
        let total = 4096 + json.len().max(1);
        // hdr_size must exceed binary header
        let hdr_size = (4096 + 4096) as u64; // 8192, JSON area 4096
        buf[8..16].copy_from_slice(&hdr_size.to_be_bytes());
        let mut area = vec![0u8; (hdr_size as usize) - 4096];
        area[..json.len()].copy_from_slice(json.as_bytes());
        buf.extend_from_slice(&area);
        let _ = total;

        let src = ByteSliceDataSource::new(buf);
        match parse(&src).unwrap() {
            LuksHeader::V2(hd) => {
                let ks = hd.meta.keyslots.get("0").unwrap();
                assert_eq!(ks.key_size, 64);
                assert_eq!(ks.af.stripes, 4000);
                assert_eq!(ks.kdf.kind, "pbkdf2");
                let seg = hd.meta.segments.get("0").unwrap();
                assert_eq!(seg.offset, "16777216");
                assert_eq!(seg.sector_size, Some(512));
                let dig = hd.meta.digests.get("0").unwrap();
                assert_eq!(dig.iterations, 2000);
            }
            _ => panic!("expected LUKS2"),
        }
    }
}
