use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Blue Iris DVR carving signature. Header: "BLUE" 20 00 10 00 (8 bytes) at offset 0. No footer.
/// PhotoRec's data_check walks "BLUE" chunks accumulating calculated_file_size;
/// that stateful walk is degraded here to a header-magic + max-size signature.
struct BvrSignature;

impl FileSignature for BvrSignature {
    fn name(&self) -> &str {
        "Blue Iris DVR"
    }
    fn extensions(&self) -> &[&str] {
        &["bvr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..8] == b"BLUE\x20\x00\x10\x00" {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "bvr".to_string(),
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
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"BLUE\x20\x00\x10\x00", Arc::new(BvrSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bvr_header_match() {
        let sig = BvrSignature;
        let buf = b"BLUE\x20\x00\x10\x00extra";
        assert!(sig.header_check(buf, 0).is_some());
    }

    #[test]
    fn test_bvr_no_match() {
        let sig = BvrSignature;
        assert!(sig.header_check(b"BLUEXXXX", 0).is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
