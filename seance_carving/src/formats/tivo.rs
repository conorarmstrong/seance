use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// TiVo video record carving signature. Ported from file_tivo.c.
/// Header: {'T','i','V','o',0x00,0x04,0x00} at offset 0, and "<?xml " at offset 0x1c.
/// Footer: {0x00,0x00,0x01,0xb7,0x00,0x00,0x01,0xb9}.
struct TivoSignature;

const MAGIC: &[u8] = &[b'T', b'i', b'V', b'o', 0x00, 0x04, 0x00];
const FOOTER: &[u8] = &[0x00, 0x00, 0x01, 0xb7, 0x00, 0x00, 0x01, 0xb9];

impl FileSignature for TivoSignature {
    fn name(&self) -> &str {
        "TiVo"
    }

    fn extensions(&self) -> &[&str] {
        &["TiVo"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x22 && &buf[0..7] == MAGIC && &buf[0x1c..0x22] == b"<?xml " {
            Some(RecoveryInit {
                min_filesize: 0x22,
                extension: "TiVo".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        if let Some(pos) = buf.windows(FOOTER.len()).position(|w| w == FOOTER) {
            return DataCheckResult::Stop(recovery.file_size + pos as u64 + FOOTER.len() as u64);
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MAGIC, Arc::new(TivoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tivo_header_match() {
        let sig = TivoSignature;
        let mut buf = vec![0u8; 0x22];
        buf[0..7].copy_from_slice(MAGIC);
        buf[0x1c..0x22].copy_from_slice(b"<?xml ");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_tivo_no_match() {
        let sig = TivoSignature;
        // Correct magic but missing the "<?xml " marker.
        let mut buf = vec![0u8; 0x22];
        buf[0..7].copy_from_slice(MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(&[0u8; 0x22], 0).is_none());
    }

    #[test]
    fn test_tivo_footer_detection() {
        let sig = TivoSignature;
        let mut recovery = FileRecovery {
            extension: "TiVo".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 0x22,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0xffu8; 4];
        buf.extend_from_slice(FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(result, DataCheckResult::Stop(100 + 4 + 8));
    }
}
