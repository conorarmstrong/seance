use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Compucon EOS Design File carving signature. Header: ASCII "Compucon EOS Design File" (24 bytes)
/// at offset 0. No footer.
/// PhotoRec's file_check walks che_block records seeking a "ConnectionInfo"
/// block; that stateful file-handle walk is degraded here to a header-magic +
/// max-size signature.
struct CheSignature;

impl FileSignature for CheSignature {
    fn name(&self) -> &str {
        "Compucon EOS Design"
    }
    fn extensions(&self) -> &[&str] {
        &["che"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 24 && &buf[0..24] == b"Compucon EOS Design File" {
            Some(RecoveryInit {
                min_filesize: 0x19,
                extension: "che".to_string(),
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
    registry.register(0, b"Compucon EOS Design File", Arc::new(CheSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_che_header_match() {
        let sig = CheSignature;
        let buf = b"Compucon EOS Design File\x00\x00";
        assert!(sig.header_check(buf, 0).is_some());
    }

    #[test]
    fn test_che_no_match() {
        let sig = CheSignature;
        assert!(sig.header_check(b"Compucon EOS Design XXXX", 0).is_none());
        assert!(sig.header_check(b"short", 0).is_none());
    }
}
