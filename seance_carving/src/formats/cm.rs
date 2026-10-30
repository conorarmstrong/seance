use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Comic Life carving signature. Header: "fLmC0001" at offset 0 (8 bytes). No footer, no encoded
/// size.
const CM_MAGIC: &[u8] = b"fLmC0001";

struct CmSignature;

impl FileSignature for CmSignature {
    fn name(&self) -> &str {
        "COMICDOC"
    }
    fn extensions(&self) -> &[&str] {
        &["comicdoc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..8] == CM_MAGIC {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "comicdoc".to_string(),
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
    registry.register(0, CM_MAGIC, Arc::new(CmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cm_header_match() {
        assert!(CmSignature.header_check(b"fLmC0001rest", 0).is_some());
    }

    #[test]
    fn test_cm_no_match() {
        assert!(CmSignature.header_check(b"fLmC0002", 0).is_none());
        assert!(CmSignature.header_check(b"XXXX", 0).is_none());
    }
}
