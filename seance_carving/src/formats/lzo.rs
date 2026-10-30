use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// LZO archive carving signature. Header: 9-byte magic 0x89 'L' 'Z' 'O' 0x00 0x0d 0x0a 0x1a 0x0a at
/// offset 0. No footer.
struct LzoSignature;

const LZO_MAGIC: &[u8] = &[0x89, b'L', b'Z', b'O', 0x00, 0x0d, 0x0a, 0x1a, 0x0a];

impl FileSignature for LzoSignature {
    fn name(&self) -> &str {
        "LZO"
    }
    fn extensions(&self) -> &[&str] {
        &["lzo"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= LZO_MAGIC.len() && &buf[0..LZO_MAGIC.len()] == LZO_MAGIC {
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "lzo".to_string(),
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
    registry.register(0, LZO_MAGIC, Arc::new(LzoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lzo_header_match() {
        let sig = LzoSignature;
        assert!(sig.header_check(LZO_MAGIC, 0).is_some());
    }

    #[test]
    fn test_lzo_no_match() {
        let sig = LzoSignature;
        assert!(sig
            .header_check(b"\x89LZP\x00\x0d\x0a\x1a\x0a", 0)
            .is_none());
        assert!(sig.header_check(b"NOTLZO", 0).is_none());
    }
}
