use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Zortrax 3D printing (ZCODE) carving signature. Header: "ZCode\0\0\0" (8 bytes) at offset 0.
/// Magic-only match; no footer or size.
struct ZcodeSignature;

const ZCODE_MAGIC: &[u8] = &[b'Z', b'C', b'o', b'd', b'e', 0x00, 0x00, 0x00];

impl FileSignature for ZcodeSignature {
    fn name(&self) -> &str {
        "ZCODE"
    }

    fn extensions(&self) -> &[&str] {
        &["zcode"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= ZCODE_MAGIC.len() && &buf[0..ZCODE_MAGIC.len()] == ZCODE_MAGIC {
            Some(RecoveryInit {
                min_filesize: ZCODE_MAGIC.len() as u64,
                extension: "zcode".to_string(),
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
    registry.register(0, ZCODE_MAGIC, Arc::new(ZcodeSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zcode_header_match() {
        let sig = ZcodeSignature;
        assert!(sig.header_check(b"ZCode\x00\x00\x00extra", 0).is_some());
    }

    #[test]
    fn test_zcode_no_match() {
        let sig = ZcodeSignature;
        assert!(sig.header_check(b"ZCode\x01\x00\x00", 0).is_none());
        assert!(sig.header_check(b"NOTZCODE", 0).is_none());
    }
}
