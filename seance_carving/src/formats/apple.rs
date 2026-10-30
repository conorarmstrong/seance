use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AppleSingle/AppleDouble carving signature. Header: 00 05 16 07 00 02 00 00 at offset 0 (8
/// bytes). No footer; max-size cutoff.
struct AppleSignature;

const APPLE_MAGIC: &[u8] = &[0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00];

impl FileSignature for AppleSignature {
    fn name(&self) -> &str {
        "APPLE"
    }
    fn extensions(&self) -> &[&str] {
        &["apple"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= APPLE_MAGIC.len() && &buf[0..APPLE_MAGIC.len()] == APPLE_MAGIC {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "apple".to_string(),
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
    registry.register(0, APPLE_MAGIC, Arc::new(AppleSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apple_header_match() {
        let sig = AppleSignature;
        let mut buf = APPLE_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_apple_no_match() {
        let sig = AppleSignature;
        // Wrong second byte.
        assert!(sig
            .header_check(&[0x00, 0x06, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00], 0)
            .is_none());
        // Too short.
        assert!(sig.header_check(&[0x00, 0x05, 0x16], 0).is_none());
    }
}
