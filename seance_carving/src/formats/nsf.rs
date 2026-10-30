use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// NSF (Lotus Notes) carving signature. Header: magic {0x1a,0x00,0x00,0x04,0x00,0x00} at offset 0,
/// plus the bytes
/// 0x25 0x85 at offsets 0x10/0x11. No footer; header-only detection.
struct NsfSignature;

impl FileSignature for NsfSignature {
    fn name(&self) -> &str {
        "NSF"
    }
    fn extensions(&self) -> &[&str] {
        &["nsf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x12
            && buf[0..6] == [0x1a, 0x00, 0x00, 0x04, 0x00, 0x00]
            && buf[0x10] == 0x25
            && buf[0x11] == 0x85
        {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "nsf".to_string(),
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
    registry.register(
        0,
        &[0x1a, 0x00, 0x00, 0x04, 0x00, 0x00],
        Arc::new(NsfSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsf_header_match() {
        let sig = NsfSignature;
        let mut buf = vec![0u8; 0x12];
        buf[0..6].copy_from_slice(&[0x1a, 0x00, 0x00, 0x04, 0x00, 0x00]);
        buf[0x10] = 0x25;
        buf[0x11] = 0x85;
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_nsf_no_match() {
        let sig = NsfSignature;
        // Correct leading magic but wrong secondary bytes.
        let mut buf = vec![0u8; 0x12];
        buf[0..6].copy_from_slice(&[0x1a, 0x00, 0x00, 0x04, 0x00, 0x00]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        let buf2 = vec![0u8; 0x12];
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
