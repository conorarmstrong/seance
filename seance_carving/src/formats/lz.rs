use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// lzip compressed file (LZ) carving signature. Header: "LZIP" 01 (5 bytes) at offset 0. No footer.
struct LzSignature;

impl FileSignature for LzSignature {
    fn name(&self) -> &str {
        "lzip compressed file"
    }
    fn extensions(&self) -> &[&str] {
        &["lz"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        const MAGIC: &[u8] = &[b'L', b'Z', b'I', b'P', 0x01];
        if buf.len() >= 5 && &buf[0..5] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 5,
                extension: "lz".to_string(),
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
    registry.register(0, &[b'L', b'Z', b'I', b'P', 0x01], Arc::new(LzSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz_header_match() {
        let sig = LzSignature;
        assert!(sig.header_check(b"LZIP\x01\x00", 0).is_some());
    }

    #[test]
    fn test_lz_no_match() {
        let sig = LzSignature;
        assert!(sig.header_check(b"LZIP\x02", 0).is_none());
        assert!(sig.header_check(b"LZ", 0).is_none());
    }
}
