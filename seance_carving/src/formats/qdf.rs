use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Quicken carving signature. Header: {0xAC,0x9E,0xBD,0x8F,0x00,0x00} at offset 0. No footer; size
/// not encoded.
struct QdfSignature;

const QDF_MAGIC: [u8; 6] = [0xAC, 0x9E, 0xBD, 0x8F, 0x00, 0x00];

impl FileSignature for QdfSignature {
    fn name(&self) -> &str {
        "QDF"
    }
    fn extensions(&self) -> &[&str] {
        &["qdf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 6 && buf[0..6] == QDF_MAGIC {
            Some(RecoveryInit {
                min_filesize: 6,
                extension: "qdf".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &QDF_MAGIC, Arc::new(QdfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qdf_header_match() {
        assert!(QdfSignature.header_check(&QDF_MAGIC, 0).is_some());
    }

    #[test]
    fn test_qdf_no_match() {
        assert!(QdfSignature
            .header_check(&[0xAC, 0x9E, 0xBD, 0x00, 0x00, 0x00], 0)
            .is_none());
        assert!(QdfSignature.header_check(b"abc", 0).is_none());
    }
}
