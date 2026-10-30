use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Synology AES key carving signature. Header: ASCII "323382b3c4f1c6d2" (16 bytes) at offset 0.
/// Fixed size: exactly 32 bytes (calculated_file_size in the source).
struct KeySignature;

impl FileSignature for KeySignature {
    fn name(&self) -> &str {
        "Synology AES key"
    }
    fn extensions(&self) -> &[&str] {
        &["key"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        const MAGIC: &[u8] = b"323382b3c4f1c6d2";
        if buf.len() >= 16 && &buf[0..16] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 32,
                extension: "key".to_string(),
                calculated_file_size: Some(32),
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
    registry.register(0, b"323382b3c4f1c6d2", Arc::new(KeySignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_header_match() {
        let sig = KeySignature;
        let init = sig
            .header_check(b"323382b3c4f1c6d2\x00\x00", 0)
            .expect("magic should match");
        assert_eq!(init.calculated_file_size, Some(32));
    }

    #[test]
    fn test_key_no_match() {
        let sig = KeySignature;
        assert!(sig.header_check(b"323382b3c4f1c6d3", 0).is_none());
        assert!(sig.header_check(b"short", 0).is_none());
    }
}
