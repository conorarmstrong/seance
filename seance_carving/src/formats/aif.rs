use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Audio Interchange File Format (AIFF/AIFC) carving signature.
/// Header: "FORM" at offset 0, big-endian chunk size at offset 4 (>= 4), and a
/// form type at offset 8: "AIFF"/"AIFC" (extension "aif") or "ILBMBMHD"
/// (extension "iff"). File size = chunk size + 8. No footer.
struct AifSignature;

const AIF_MAGIC: &[u8] = b"FORM";

impl FileSignature for AifSignature {
    fn name(&self) -> &str {
        "AIF"
    }

    fn extensions(&self) -> &[&str] {
        &["aif", "iff"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 || &buf[0..4] != AIF_MAGIC {
            return None;
        }
        let ck_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        if ck_size < 4 {
            return None;
        }
        let calculated_file_size = Some(ck_size + 8);
        // AIFF / AIFC audio.
        if &buf[8..11] == b"AIF" && (buf[11] == b'F' || buf[11] == b'C') {
            return Some(RecoveryInit {
                min_filesize: 12,
                extension: "aif".to_string(),
                calculated_file_size,
            });
        }
        // ILBM interleaved bitmap (IFF).
        if buf.len() >= 16 && &buf[8..16] == b"ILBMBMHD" {
            return Some(RecoveryInit {
                min_filesize: 12,
                extension: "iff".to_string(),
                calculated_file_size,
            });
        }
        None
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
    registry.register(0, AIF_MAGIC, Arc::new(AifSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aif_header_match() {
        let sig = AifSignature;
        // "FORM" + big-endian size 100 + "AIFF".
        let buf = [
            b'F', b'O', b'R', b'M', 0x00, 0x00, 0x00, 0x64, b'A', b'I', b'F', b'F',
        ];
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "aif");
        assert_eq!(init.calculated_file_size, Some(100 + 8));
    }

    #[test]
    fn test_aif_iff_extension() {
        let sig = AifSignature;
        let buf = [
            b'F', b'O', b'R', b'M', 0x00, 0x00, 0x00, 0x64, b'I', b'L', b'B', b'M', b'B', b'M',
            b'H', b'D',
        ];
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "iff");
    }

    #[test]
    fn test_aif_no_match() {
        let sig = AifSignature;
        // Chunk size below minimum (2 < 4).
        let small = [
            b'F', b'O', b'R', b'M', 0x00, 0x00, 0x00, 0x02, b'A', b'I', b'F', b'F',
        ];
        assert!(sig.header_check(&small, 0).is_none());
        // Unknown form type.
        let bad = [
            b'F', b'O', b'R', b'M', 0x00, 0x00, 0x00, 0x64, b'J', b'U', b'N', b'K',
        ];
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
