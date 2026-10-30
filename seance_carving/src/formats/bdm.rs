use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AVCHD index (BDM) carving signature. Header: "INDX0100" or "MOBJ0100" (8 bytes) at offset 0. No
/// footer or embedded size.
struct BdmSignature;

impl FileSignature for BdmSignature {
    fn name(&self) -> &str {
        "BDM"
    }

    fn extensions(&self) -> &[&str] {
        &["bdm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && (&buf[0..8] == b"INDX0100" || &buf[0..8] == b"MOBJ0100") {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "bdm".to_string(),
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
    registry.register(0, b"INDX0100", Arc::new(BdmSignature));
    registry.register(0, b"MOBJ0100", Arc::new(BdmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bdm_header_match() {
        let sig = BdmSignature;
        assert!(sig.header_check(b"INDX0100extra", 0).is_some());
        assert!(sig.header_check(b"MOBJ0100extra", 0).is_some());
    }

    #[test]
    fn test_bdm_no_match() {
        let sig = BdmSignature;
        assert!(sig.header_check(b"INDX0200", 0).is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
