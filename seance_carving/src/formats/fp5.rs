use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FileMaker Pro carving signature. Header: 16-byte magic 00 01 00 00 00 02 00 01 00 05 00 02 00 02
/// c0 00 at
/// offset 0. Header-only, no footer or fixed size.
struct Fp5Signature;

const FP5_MAGIC: &[u8] = &[
    0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x00, 0x02, 0x00, 0x02, 0xc0, 0x00,
];

impl FileSignature for Fp5Signature {
    fn name(&self) -> &str {
        "FileMaker Pro"
    }
    fn extensions(&self) -> &[&str] {
        &["fp5"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= FP5_MAGIC.len() && &buf[0..FP5_MAGIC.len()] == FP5_MAGIC {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "fp5".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, FP5_MAGIC, Arc::new(Fp5Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp5_header_match() {
        let sig = Fp5Signature;
        let mut buf = FP5_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_fp5_no_match() {
        let sig = Fp5Signature;
        assert!(sig.header_check(&[0x00, 0x01, 0x00, 0x00], 0).is_none());
        assert!(sig.header_check(&[0xffu8; 16], 0).is_none());
    }
}
