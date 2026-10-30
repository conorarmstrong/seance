use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Mikron image carving signature. Header: 14 bytes at offset 0: "7100 3.3D 7100". No footer.
struct SitSignature;

const SIT_MAGIC: &[u8] = b"7100 3.3D 7100";

impl FileSignature for SitSignature {
    fn name(&self) -> &str {
        "Mikron image"
    }
    fn extensions(&self) -> &[&str] {
        &["sit"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SIT_MAGIC.len() && &buf[0..SIT_MAGIC.len()] == SIT_MAGIC {
            Some(RecoveryInit {
                min_filesize: SIT_MAGIC.len() as u64,
                extension: "sit".to_string(),
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
    registry.register(0, SIT_MAGIC, Arc::new(SitSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sit_header_match() {
        let sig = SitSignature;
        assert!(sig.header_check(b"7100 3.3D 7100\x00", 0).is_some());
    }

    #[test]
    fn test_sit_no_match() {
        let sig = SitSignature;
        assert!(sig.header_check(b"7100 3.3D 7200", 0).is_none());
        assert!(sig.header_check(b"7100 3.3D", 0).is_none());
    }
}
