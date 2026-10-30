use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// KeePassX (KDBX) carving signature. Header: 03 d9 a2 9a 67 fb 4b b5 at offset 0. No footer;
/// min_filesize 124.
struct KdbxSignature;

impl FileSignature for KdbxSignature {
    fn name(&self) -> &str {
        "KeePassX"
    }
    fn extensions(&self) -> &[&str] {
        &["kdbx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        const MAGIC: &[u8] = &[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
        if buf.len() >= 8 && &buf[0..8] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 124,
                extension: "kdbx".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5],
        Arc::new(KdbxSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdbx_header_match() {
        let sig = KdbxSignature;
        let buf = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x00];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_kdbx_no_match() {
        let sig = KdbxSignature;
        // kdb variant (0x65) must not match kdbx (0x67)
        let buf = [0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5, 0x00];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"NOTKDBX", 0).is_none());
    }
}
