use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Logic Platinum File carving signature. Header: 14-byte magic
/// {0x13,'G',0xc0,0xab,0x17,0x05,0x15,0x00,0x03,0x00,0x24,0x00,0x24,0x00} at offset 0.
/// Footer: {0xFF,0xFF,0xFF,0x7F,0x7F,0x7F} plus 0x46 trailing bytes (file_search_footer extra_length).
struct LsoSignature;

const LSO_MAGIC: [u8; 14] = [
    0x13, b'G', 0xc0, 0xab, 0x17, 0x05, 0x15, 0x00, 0x03, 0x00, 0x24, 0x00, 0x24, 0x00,
];
const LSO_FOOTER: [u8; 6] = [0xFF, 0xFF, 0xFF, 0x7F, 0x7F, 0x7F];
const LSO_FOOTER_EXTRA: u64 = 0x46;

impl FileSignature for LsoSignature {
    fn name(&self) -> &str {
        "LSO"
    }
    fn extensions(&self) -> &[&str] {
        &["lso"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= LSO_MAGIC.len() && buf[0..LSO_MAGIC.len()] == LSO_MAGIC {
            Some(RecoveryInit {
                min_filesize: 14,
                extension: "lso".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Scan for the LSO footer; final size includes footer + 0x46 extra bytes.
        match footer_end_spanning(buf, recovery, &LSO_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end + LSO_FOOTER_EXTRA),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &LSO_MAGIC, Arc::new(LsoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lso_header_match() {
        let sig = LsoSignature;
        let mut buf = LSO_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_lso_no_match() {
        let sig = LsoSignature;
        assert!(sig.header_check(b"NOTANLSOFILE00", 0).is_none());
        assert!(sig.header_check(&[0x13, b'G'], 0).is_none());
    }

    #[test]
    fn test_lso_footer_stop() {
        let sig = LsoSignature;
        let mut recovery = FileRecovery {
            extension: "lso".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 14,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0u8; 4];
        buf.extend_from_slice(&LSO_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(
            result,
            DataCheckResult::Stop(100 + 4 + LSO_FOOTER.len() as u64 + LSO_FOOTER_EXTRA)
        );
    }
}
