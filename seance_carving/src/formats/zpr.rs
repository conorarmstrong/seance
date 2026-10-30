use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ZBrush (ZPR) carving signature. Header: "ZBrush File." (12 bytes) at offset 0, plus "RPZ" at
/// offset 0x4c.
/// No footer or embedded size.
struct ZprSignature;

const ZPR_MAGIC: &[u8] = b"ZBrush File.";

impl FileSignature for ZprSignature {
    fn name(&self) -> &str {
        "ZPR"
    }

    fn extensions(&self) -> &[&str] {
        &["zpr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x4f
            && &buf[0..ZPR_MAGIC.len()] == ZPR_MAGIC
            && buf[0x4c] == b'R'
            && buf[0x4d] == b'P'
            && buf[0x4e] == b'Z'
        {
            Some(RecoveryInit {
                min_filesize: 0x4f,
                extension: "zpr".to_string(),
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
    registry.register(0, ZPR_MAGIC, Arc::new(ZprSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zpr_header_match() {
        let sig = ZprSignature;
        let mut buf = vec![0u8; 0x4f];
        buf[0..ZPR_MAGIC.len()].copy_from_slice(ZPR_MAGIC);
        buf[0x4c] = b'R';
        buf[0x4d] = b'P';
        buf[0x4e] = b'Z';
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_zpr_no_match() {
        let sig = ZprSignature;
        // Correct leading magic but missing trailing "RPZ".
        let mut buf = vec![0u8; 0x4f];
        buf[0..ZPR_MAGIC.len()].copy_from_slice(ZPR_MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        assert!(sig.header_check(b"NotZBrush...", 0).is_none());
    }
}
