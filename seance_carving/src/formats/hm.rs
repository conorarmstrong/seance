use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// HyperMesh (structural analysis) carving signature. Header: fixed 23-byte magic at offset 0
/// (embeds a gzip stream
/// header 1f 8b 08). No footer; header_check always accepts on magic match.
struct HmSignature;

const HM_MAGIC: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x1f, 0x8b, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0xed,
];

impl FileSignature for HmSignature {
    fn name(&self) -> &str {
        "HM"
    }
    fn extensions(&self) -> &[&str] {
        &["hm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 23 && &buf[0..23] == HM_MAGIC {
            Some(RecoveryInit {
                min_filesize: 23,
                extension: "hm".to_string(),
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
    registry.register(0, HM_MAGIC, Arc::new(HmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hm_header_match() {
        let sig = HmSignature;
        assert!(sig.header_check(HM_MAGIC, 0).is_some());
    }

    #[test]
    fn test_hm_no_match() {
        let sig = HmSignature;
        assert!(sig.header_check(&[0xFFu8; 23], 0).is_none());
        assert!(sig.header_check(&[0u8; 10], 0).is_none());
    }
}
