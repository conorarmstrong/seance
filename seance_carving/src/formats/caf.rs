use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Core Audio Format carving signature. Header: "caff" 00 01 00 00 "desc" (12 bytes) at offset 0.
/// No footer.
/// PhotoRec's data_check walks big-endian sized chunks accumulating
/// calculated_file_size; that stateful walk is degraded here to a
/// header-magic + max-size signature.
struct CafSignature;

impl FileSignature for CafSignature {
    fn name(&self) -> &str {
        "Core Audio Format"
    }
    fn extensions(&self) -> &[&str] {
        &["caf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..12] == b"caff\x00\x01\x00\x00desc" {
            Some(RecoveryInit {
                min_filesize: 20, // 8 (header) + 12 (first chunk)
                extension: "caf".to_string(),
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
    registry.register(0, b"caff\x00\x01\x00\x00desc", Arc::new(CafSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caf_header_match() {
        let sig = CafSignature;
        let mut buf = b"caff\x00\x01\x00\x00desc".to_vec();
        buf.extend_from_slice(&[0u8; 8]); // chunk size
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_caf_no_match() {
        let sig = CafSignature;
        assert!(sig.header_check(b"caff\x00\x02\x00\x00desc", 0).is_none());
        assert!(sig.header_check(b"NOTAUDIOxxxx", 0).is_none());
    }
}
