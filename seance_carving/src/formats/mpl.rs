use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MPL (AVCHD playlist) carving signature. Header: ASCII "MPLS0100" at offset 0. No footer;
/// header-only detection.
struct MplSignature;

impl FileSignature for MplSignature {
    fn name(&self) -> &str {
        "MPL"
    }
    fn extensions(&self) -> &[&str] {
        &["mpl"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..8] == b"MPLS0100" {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "mpl".to_string(),
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
    registry.register(0, b"MPLS0100", Arc::new(MplSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpl_header_match() {
        let sig = MplSignature;
        assert!(sig.header_check(b"MPLS0100extra", 0).is_some());
    }

    #[test]
    fn test_mpl_no_match() {
        let sig = MplSignature;
        assert!(sig.header_check(b"MPLS0101extra", 0).is_none());
        assert!(sig.header_check(b"NOMATCH!", 0).is_none());
    }
}
