use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// KeePassX (KDB) carving signature. Header: 03 d9 a2 9a 65 fb 4b b5 at offset 0. No footer;
/// min_filesize 124.
struct KdbSignature;

impl FileSignature for KdbSignature {
    fn name(&self) -> &str {
        "KeePassX"
    }
    fn extensions(&self) -> &[&str] {
        &["kdb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        const MAGIC: &[u8] = &[0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5];
        if buf.len() >= 8 && &buf[0..8] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 124,
                extension: "kdb".to_string(),
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
        &[0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5],
        Arc::new(KdbSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdb_header_match() {
        let sig = KdbSignature;
        let buf = [0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5, 0x00];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_kdb_no_match() {
        let sig = KdbSignature;
        // kdbx variant (0x67) must not match kdb (0x65)
        let buf = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x00];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"NOTKDB", 0).is_none());
    }
}
