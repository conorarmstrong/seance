use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// EnCase Expert Witness (EWF/E01) carving signature. Header (offset 0): "EVF" 0x09 0x0d 0x0a 0xff
/// 0x00 0x01 (EWF file signature).
/// Degraded: PhotoRec's file_check footer search (next/done section markers) and the
/// dynamic E0x/EAB extension derived from the segment number are not implemented.
struct E01Signature;

const E01_MAGIC: &[u8] = b"EVF\x09\x0d\x0a\xff\x00\x01";

impl FileSignature for E01Signature {
    fn name(&self) -> &str {
        "E01"
    }

    fn extensions(&self) -> &[&str] {
        &["e01"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= E01_MAGIC.len() && &buf[..E01_MAGIC.len()] == E01_MAGIC {
            Some(RecoveryInit {
                min_filesize: 13,
                extension: "e01".to_string(),
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
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, E01_MAGIC, Arc::new(E01Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e01_header_match() {
        let sig = E01Signature;
        assert!(sig
            .header_check(b"EVF\x09\x0d\x0a\xff\x00\x01\x00\x00", 0)
            .is_some());
    }

    #[test]
    fn test_e01_no_match() {
        let sig = E01Signature;
        assert!(sig
            .header_check(b"EVF\x09\x0d\x0a\xff\x00\x00\x00", 0)
            .is_none());
        assert!(sig.header_check(b"NOTEVF", 0).is_none());
    }
}
