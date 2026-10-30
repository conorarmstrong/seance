use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AutoSketch drawing carving signature. Header: 29 bytes at offset 0: "AutoSketch drawing
/// database\r\n". No footer.
struct SkdSignature;

const SKD_MAGIC: &[u8] = b"AutoSketch drawing database\r\n";

impl FileSignature for SkdSignature {
    fn name(&self) -> &str {
        "AutoSketch drawing"
    }
    fn extensions(&self) -> &[&str] {
        &["skd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SKD_MAGIC.len() && &buf[0..SKD_MAGIC.len()] == SKD_MAGIC {
            Some(RecoveryInit {
                min_filesize: SKD_MAGIC.len() as u64,
                extension: "skd".to_string(),
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
    registry.register(0, SKD_MAGIC, Arc::new(SkdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skd_header_match() {
        let sig = SkdSignature;
        assert!(sig
            .header_check(b"AutoSketch drawing database\r\n\x00", 0)
            .is_some());
    }

    #[test]
    fn test_skd_no_match() {
        let sig = SkdSignature;
        assert!(sig
            .header_check(b"AutoSketch drawing databaseXX", 0)
            .is_none());
        assert!(sig.header_check(b"AutoSketch", 0).is_none());
    }
}
