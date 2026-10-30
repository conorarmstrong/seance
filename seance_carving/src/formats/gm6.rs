use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Game Maker (4.3 - 8.1) project carving signature. Header at offset 0: 4-byte constant
/// 0x001234321 (91 d5 12 00, little-endian
/// 1234321) followed by a little-endian version word at offset 4. The version word
/// selects the extension: gm81 / gmk / gm6 / gmd.
struct Gm6Signature;

const GM6_PREFIX: &[u8] = &[0x91, 0xd5, 0x12, 0x00];

/// Each registered magic is the 4-byte prefix plus the 4-byte version word.
const GM6_HEADERS: &[[u8; 8]] = &[
    [0x91, 0xd5, 0x12, 0x00, 0x2a, 0x03, 0x00, 0x00], // 8.1  -> gm81
    [0x91, 0xd5, 0x12, 0x00, 0x20, 0x03, 0x00, 0x00], // 8.0  -> gmk
    [0x91, 0xd5, 0x12, 0x00, 0xbe, 0x02, 0x00, 0x00], // 7.0v2 -> gmk
    [0x91, 0xd5, 0x12, 0x00, 0xbd, 0x02, 0x00, 0x00], // 7.0v1 -> gmk
    [0x91, 0xd5, 0x12, 0x00, 0x6c, 0x02, 0x00, 0x00], // 7.0e -> gmk
    [0x91, 0xd5, 0x12, 0x00, 0x58, 0x02, 0x00, 0x00], // 6.0-6.1 -> gm6
    [0x91, 0xd5, 0x12, 0x00, 0x12, 0x02, 0x00, 0x00], // 5.3  -> gmd
    [0x91, 0xd5, 0x12, 0x00, 0x08, 0x02, 0x00, 0x00], // 5.2  -> gmd
    [0x91, 0xd5, 0x12, 0x00, 0xfe, 0x01, 0x00, 0x00], // 5.1  -> gmd
    [0x91, 0xd5, 0x12, 0x00, 0xf4, 0x01, 0x00, 0x00], // 5.0  -> gmd
    [0x91, 0xd5, 0x12, 0x00, 0xae, 0x01, 0x00, 0x00], // 4.3  -> gmd
];

impl FileSignature for Gm6Signature {
    fn name(&self) -> &str {
        "Game Maker"
    }
    fn extensions(&self) -> &[&str] {
        &["gm81", "gmk", "gm6", "gmd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..4] == GM6_PREFIX {
            let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let ext = match version {
                0x0000_032a => "gm81",
                0x0000_0320 | 0x0000_02be | 0x0000_02bd | 0x0000_026c => "gmk",
                0x0000_0258 => "gm6",
                0x0000_0212 | 0x0000_0208 | 0x0000_01fe | 0x0000_01f4 | 0x0000_01ae => "gmd",
                _ => return None,
            };
            Some(RecoveryInit {
                min_filesize: 8,
                extension: ext.to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    for header in GM6_HEADERS {
        registry.register(0, header, Arc::new(Gm6Signature));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gm6_header_match() {
        let sig = Gm6Signature;
        // 8.1 version -> gm81
        let init = sig.header_check(&GM6_HEADERS[0], 0).unwrap();
        assert_eq!(init.extension, "gm81");
        // 6.0 version -> gm6
        let init = sig.header_check(&GM6_HEADERS[5], 0).unwrap();
        assert_eq!(init.extension, "gm6");
        // 4.3 version -> gmd
        let init = sig.header_check(&GM6_HEADERS[10], 0).unwrap();
        assert_eq!(init.extension, "gmd");
    }

    #[test]
    fn test_gm6_no_match() {
        let sig = Gm6Signature;
        // correct prefix but unknown version word
        let mut bad = GM6_PREFIX.to_vec();
        bad.extend_from_slice(&[0x99, 0x99, 0x00, 0x00]);
        assert!(sig.header_check(&bad, 0).is_none());
        // wrong prefix
        assert!(sig
            .header_check(&[0x00, 0x00, 0x00, 0x00, 0x2a, 0x03, 0x00, 0x00], 0)
            .is_none());
    }
}
