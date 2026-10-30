use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Binvox voxel file carving signature. Header: "#binvox 1\ndim " (14 bytes) at offset 0. No footer
/// or embedded size.
const BINVOX_MAGIC: &[u8] = b"#binvox 1\ndim ";

struct BinvoxSignature;

impl FileSignature for BinvoxSignature {
    fn name(&self) -> &str {
        "BINVOX"
    }

    fn extensions(&self) -> &[&str] {
        &["binvox"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= BINVOX_MAGIC.len() && &buf[0..BINVOX_MAGIC.len()] == BINVOX_MAGIC {
            Some(RecoveryInit {
                min_filesize: BINVOX_MAGIC.len() as u64,
                extension: "binvox".to_string(),
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
    registry.register(0, BINVOX_MAGIC, Arc::new(BinvoxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binvox_header_match() {
        let sig = BinvoxSignature;
        assert!(sig.header_check(b"#binvox 1\ndim 32 32 32\n", 0).is_some());
    }

    #[test]
    fn test_binvox_no_match() {
        let sig = BinvoxSignature;
        assert!(sig.header_check(b"#binvox 2\ndim ", 0).is_none());
        assert!(sig.header_check(b"not a binvox", 0).is_none());
    }
}
