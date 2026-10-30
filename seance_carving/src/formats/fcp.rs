use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Final Cut Pro carving signature. Header: 0xA2 "KeyG" (5 bytes) at offset 0. No footer/size.
struct FcpSignature;

const MAGIC: [u8; 5] = [0xA2, b'K', b'e', b'y', b'G'];

impl FileSignature for FcpSignature {
    fn name(&self) -> &str {
        "Final Cut Pro"
    }
    fn extensions(&self) -> &[&str] {
        &["fcp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 5 && buf[0..5] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 5,
                extension: "fcp".to_string(),
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
    registry.register(0, &MAGIC, Arc::new(FcpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fcp_header_match() {
        let sig = FcpSignature;
        assert!(sig.header_check(b"\xA2KeyG\x00", 0).is_some());
    }

    #[test]
    fn test_fcp_no_match() {
        let sig = FcpSignature;
        assert!(sig.header_check(b"\xA2KeyX", 0).is_none());
        assert!(sig.header_check(b"KeyG", 0).is_none());
    }
}
