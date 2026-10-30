use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// RT60 index (IDX) carving signature. Header: magic "RT60" at offset 0, and a second "RT60" marker
/// at offset 0x18.
/// PhotoRec sizes the file by counting consecutive 0x30-byte records that each
/// begin with "RT60"; that stateful data_check is degraded here to a header
/// magic plus max-size carve (see note).
struct IdxSignature;

impl FileSignature for IdxSignature {
    fn name(&self) -> &str {
        "RT60"
    }

    fn extensions(&self) -> &[&str] {
        &["idx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x1C && &buf[0x18..0x1C] == b"RT60" {
            Some(RecoveryInit {
                min_filesize: 0x30,
                extension: "idx".to_string(),
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
    registry.register(0, b"RT60", Arc::new(IdxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idx_header_match() {
        let sig = IdxSignature;
        let mut buf = vec![0u8; 0x30];
        buf[0..4].copy_from_slice(b"RT60");
        buf[0x18..0x1C].copy_from_slice(b"RT60");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_idx_no_match() {
        let sig = IdxSignature;
        let mut buf = vec![0u8; 0x30];
        buf[0..4].copy_from_slice(b"RT60"); // marker at 0x18 missing
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"RT60", 0).is_none()); // too short
    }
}
