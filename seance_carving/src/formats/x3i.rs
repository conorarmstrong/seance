use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Sigma/Foveon X3 raw picture carving signature. Header: "FOVi" 0x00 0x00 0x01 0x00 at offset 0.
/// Minimum file size 1024. No footer.
struct X3iSignature;

const X3I_MAGIC: &[u8] = b"FOVi\x00\x00\x01\x00";

impl FileSignature for X3iSignature {
    fn name(&self) -> &str {
        "X3I"
    }
    fn extensions(&self) -> &[&str] {
        &["x3i"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= X3I_MAGIC.len() && &buf[0..X3I_MAGIC.len()] == X3I_MAGIC {
            Some(RecoveryInit {
                min_filesize: 1024,
                extension: "x3i".to_string(),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, X3I_MAGIC, Arc::new(X3iSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x3i_header_match() {
        assert!(X3iSignature.header_check(X3I_MAGIC, 0).is_some());
    }

    #[test]
    fn test_x3i_no_match() {
        assert!(X3iSignature
            .header_check(b"FOVi\x00\x00\x02\x00", 0)
            .is_none());
        assert!(X3iSignature.header_check(b"FOVi", 0).is_none());
    }
}
