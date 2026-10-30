use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Apple Logic Studio (LOGIC) carving signature.
/// Header: ab c0 47 13 05 17 00 15 00 04 00 24 (12 bytes) at offset 0. No footer.
struct LogicSignature;

impl FileSignature for LogicSignature {
    fn name(&self) -> &str {
        "Apple Logic Studio"
    }
    fn extensions(&self) -> &[&str] {
        &["logic"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        const MAGIC: &[u8] = &[
            0xab, 0xc0, 0x47, 0x13, 0x05, 0x17, 0x00, 0x15, 0x00, 0x04, 0x00, 0x24,
        ];
        if buf.len() >= 12 && &buf[0..12] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 12,
                extension: "logic".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[
            0xab, 0xc0, 0x47, 0x13, 0x05, 0x17, 0x00, 0x15, 0x00, 0x04, 0x00, 0x24,
        ],
        Arc::new(LogicSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logic_header_match() {
        let sig = LogicSignature;
        let buf = [
            0xab, 0xc0, 0x47, 0x13, 0x05, 0x17, 0x00, 0x15, 0x00, 0x04, 0x00, 0x24, 0x00,
        ];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_logic_no_match() {
        let sig = LogicSignature;
        let buf = [
            0xab, 0xc0, 0x47, 0x13, 0x05, 0x17, 0x00, 0x15, 0x00, 0x04, 0x00, 0x00,
        ];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
