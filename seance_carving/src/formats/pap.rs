use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Papyrus word file carving signature. Header: "PAP1" at offset 0. No footer, no size. Max
/// filesize 1 MB.
struct PapSignature;

impl FileSignature for PapSignature {
    fn name(&self) -> &str {
        "Papyrus"
    }
    fn extensions(&self) -> &[&str] {
        &["pap"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 4 && &buf[0..4] == b"PAP1" {
            Some(RecoveryInit {
                min_filesize: 4,
                extension: "pap".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn weak_header(&self) -> bool {
        // No public layout past the magic and no real sample is held, so the
        // magic alone must never split a running carve (CARVE-015).
        true
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"PAP1", Arc::new(PapSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pap_header_match() {
        let sig = PapSignature;
        assert!(sig.header_check(b"PAP1\x00\x00", 0).is_some());
    }

    #[test]
    fn test_pap_no_match() {
        let sig = PapSignature;
        assert!(sig.header_check(b"PAP2", 0).is_none());
        assert!(sig.header_check(b"PA", 0).is_none());
    }
}
