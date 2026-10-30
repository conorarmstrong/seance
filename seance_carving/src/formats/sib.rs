use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Sibelius music score carving signature. Header: 9 bytes at offset 0: 0x0F followed by
/// "SIBELIUS". No footer.
struct SibSignature;

const SIB_MAGIC: &[u8] = b"\x0fSIBELIUS";

impl FileSignature for SibSignature {
    fn name(&self) -> &str {
        "Sibelius"
    }
    fn extensions(&self) -> &[&str] {
        &["sib"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SIB_MAGIC.len() && &buf[0..SIB_MAGIC.len()] == SIB_MAGIC {
            Some(RecoveryInit {
                min_filesize: SIB_MAGIC.len() as u64,
                extension: "sib".to_string(),
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
    registry.register(0, SIB_MAGIC, Arc::new(SibSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sib_header_match() {
        let sig = SibSignature;
        assert!(sig.header_check(b"\x0fSIBELIUS\x00", 0).is_some());
    }

    #[test]
    fn test_sib_no_match() {
        let sig = SibSignature;
        assert!(sig.header_check(b"\x00SIBELIUS", 0).is_none());
        assert!(sig.header_check(b"\x0fSIB", 0).is_none());
    }
}
