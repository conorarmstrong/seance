use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// RoboForm carving signature. Header at offset 0: ASCII "URL3:ver3:". No footer/size.
struct RfpSignature;

const RFP_MAGIC: &[u8] = b"URL3:ver3:";

impl FileSignature for RfpSignature {
    fn name(&self) -> &str {
        "RFP"
    }
    fn extensions(&self) -> &[&str] {
        &["rfp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= RFP_MAGIC.len() && &buf[0..RFP_MAGIC.len()] == RFP_MAGIC {
            Some(RecoveryInit {
                min_filesize: 10,
                extension: "rfp".to_string(),
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
    registry.register(0, RFP_MAGIC, Arc::new(RfpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfp_header_match() {
        let sig = RfpSignature;
        assert!(sig.header_check(b"URL3:ver3:extra", 0).is_some());
    }

    #[test]
    fn test_rfp_no_match() {
        let sig = RfpSignature;
        assert!(sig.header_check(b"URL3:ver2:", 0).is_none());
        assert!(sig.header_check(b"URL3", 0).is_none());
    }
}
