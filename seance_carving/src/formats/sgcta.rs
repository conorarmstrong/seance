use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Ciel accounting carving signature. Header: 16 bytes at offset 0: "CamBFile" followed by 01 00 00
/// 00 00 00 00 00.
/// No footer; min_filesize not set by source.
struct SgctaSignature;

const SGCTA_MAGIC: &[u8] = b"CamBFile\x01\x00\x00\x00\x00\x00\x00\x00";

impl FileSignature for SgctaSignature {
    fn name(&self) -> &str {
        "Ciel"
    }
    fn extensions(&self) -> &[&str] {
        &["sgcta"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SGCTA_MAGIC.len() && &buf[0..SGCTA_MAGIC.len()] == SGCTA_MAGIC {
            Some(RecoveryInit {
                min_filesize: SGCTA_MAGIC.len() as u64,
                extension: "sgcta".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, SGCTA_MAGIC, Arc::new(SgctaSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgcta_header_match() {
        let sig = SgctaSignature;
        assert!(sig.header_check(SGCTA_MAGIC, 0).is_some());
    }

    #[test]
    fn test_sgcta_no_match() {
        let sig = SgctaSignature;
        assert!(sig
            .header_check(b"CamBFile\x02\x00\x00\x00\x00\x00\x00\x00", 0)
            .is_none());
        assert!(sig.header_check(b"CamBFile", 0).is_none());
    }
}
