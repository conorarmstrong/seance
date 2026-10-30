use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// SymBackup carving signature. Header: "SymBakUp 1.0" + 0x0a 0x1a 0x01 (16 bytes) at offset 0. No
/// footer/size.
struct FbfSignature;

/// "SymBakUp  1.0\n\x1a\x01"
const MAGIC: [u8; 16] = [
    b'S', b'y', b'm', b'B', b'a', b'k', b'U', b'p', b' ', b' ', b'1', b'.', b'0', 0x0a, 0x1a, 0x01,
];

impl FileSignature for FbfSignature {
    fn name(&self) -> &str {
        "SymBackup"
    }
    fn extensions(&self) -> &[&str] {
        &["fbf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 16 && buf[0..16] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "fbf".to_string(),
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
    registry.register(0, &MAGIC, Arc::new(FbfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fbf_header_match() {
        let sig = FbfSignature;
        assert!(sig.header_check(&MAGIC, 0).is_some());
    }

    #[test]
    fn test_fbf_no_match() {
        let sig = FbfSignature;
        let buf = [0u8; 16];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"SymBak", 0).is_none());
    }
}
