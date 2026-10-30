use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MK5 (Custom CAD-CAM) carving signature. Header: magic {0x36,0xff,0xff,0xff} at offset 0, plus a
/// second constant
/// {0x00,0x40,0x1c,0x46} at offset 0x1c. No footer; header-only detection.
struct Mk5Signature;

impl FileSignature for Mk5Signature {
    fn name(&self) -> &str {
        "MK5"
    }
    fn extensions(&self) -> &[&str] {
        &["mk5"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x20
            && buf[0..4] == [0x36, 0xff, 0xff, 0xff]
            && buf[0x1c..0x20] == [0x00, 0x40, 0x1c, 0x46]
        {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "mk5".to_string(),
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
    registry.register(0, &[0x36, 0xff, 0xff, 0xff], Arc::new(Mk5Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mk5_header_match() {
        let sig = Mk5Signature;
        let mut buf = vec![0u8; 0x20];
        buf[0..4].copy_from_slice(&[0x36, 0xff, 0xff, 0xff]);
        buf[0x1c..0x20].copy_from_slice(&[0x00, 0x40, 0x1c, 0x46]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_mk5_no_match() {
        let sig = Mk5Signature;
        // Correct leading magic but wrong secondary constant.
        let mut buf = vec![0u8; 0x20];
        buf[0..4].copy_from_slice(&[0x36, 0xff, 0xff, 0xff]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        let buf2 = vec![0u8; 0x20];
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
