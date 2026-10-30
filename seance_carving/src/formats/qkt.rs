use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Apple QuickTake 100 carving signature. Header:
/// {'q','k','t','k',0x00,0x00,0x00,0x08} at offset 0. No footer.
struct QktSignature;

const QKT_MAGIC: [u8; 8] = [b'q', b'k', b't', b'k', 0x00, 0x00, 0x00, 0x08];

impl FileSignature for QktSignature {
    fn name(&self) -> &str {
        "QKT"
    }
    fn extensions(&self) -> &[&str] {
        &["qkt"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && buf[0..8] == QKT_MAGIC {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "qkt".to_string(),
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
        1024 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &QKT_MAGIC, Arc::new(QktSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qkt_header_match() {
        assert!(QktSignature.header_check(&QKT_MAGIC, 0).is_some());
    }

    #[test]
    fn test_qkt_no_match() {
        assert!(QktSignature
            .header_check(&[b'q', b'k', b't', b'k', 0, 0, 0, 0], 0)
            .is_none());
        assert!(QktSignature.header_check(b"qkt", 0).is_none());
    }
}
