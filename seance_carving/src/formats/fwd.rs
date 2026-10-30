use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FRWD Sports Computer carving signature. Header: ASCII "FRWD0120" at offset 0. Header-only, no
/// footer or fixed size.
struct FwdSignature;

const FWD_MAGIC: &[u8] = b"FRWD0120";

impl FileSignature for FwdSignature {
    fn name(&self) -> &str {
        "FRWD Sports Computer"
    }
    fn extensions(&self) -> &[&str] {
        &["fwd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= FWD_MAGIC.len() && &buf[0..FWD_MAGIC.len()] == FWD_MAGIC {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "fwd".to_string(),
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
    registry.register(0, FWD_MAGIC, Arc::new(FwdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fwd_header_match() {
        let sig = FwdSignature;
        assert!(sig.header_check(b"FRWD0120extra", 0).is_some());
    }

    #[test]
    fn test_fwd_no_match() {
        let sig = FwdSignature;
        assert!(sig.header_check(b"FRWD9999", 0).is_none());
        assert!(sig.header_check(b"FRWD", 0).is_none());
    }
}
