use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Rollei picture carving signature. Header: "DSC-Image" at offset 0. No footer; size not encoded.
struct RdcSignature;

impl FileSignature for RdcSignature {
    fn name(&self) -> &str {
        "RDC"
    }
    fn extensions(&self) -> &[&str] {
        &["rdc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 9 && &buf[0..9] == b"DSC-Image" {
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "rdc".to_string(),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"DSC-Image", Arc::new(RdcSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdc_header_match() {
        assert!(RdcSignature.header_check(b"DSC-Image data", 0).is_some());
    }

    #[test]
    fn test_rdc_no_match() {
        assert!(RdcSignature.header_check(b"DSC-Photo", 0).is_none());
        assert!(RdcSignature.header_check(b"DSC", 0).is_none());
    }
}
