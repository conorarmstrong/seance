use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Shorten audio file carving signature. Header: 5 bytes at offset 0: "ajkg" followed by 0x02. No
/// footer.
struct ShnSignature;

const SHN_MAGIC: &[u8] = b"ajkg\x02";

impl FileSignature for ShnSignature {
    fn name(&self) -> &str {
        "Shorten audio"
    }
    fn extensions(&self) -> &[&str] {
        &["shn"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SHN_MAGIC.len() && &buf[0..SHN_MAGIC.len()] == SHN_MAGIC {
            Some(RecoveryInit {
                min_filesize: SHN_MAGIC.len() as u64,
                extension: "shn".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, SHN_MAGIC, Arc::new(ShnSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shn_header_match() {
        let sig = ShnSignature;
        assert!(sig.header_check(b"ajkg\x02\x00\x00", 0).is_some());
    }

    #[test]
    fn test_shn_no_match() {
        let sig = ShnSignature;
        assert!(sig.header_check(b"ajkg\x01", 0).is_none());
        assert!(sig.header_check(b"ajk", 0).is_none());
    }
}
