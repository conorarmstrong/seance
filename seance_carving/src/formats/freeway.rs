use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Freeway 5 Pro carving signature. Header: 16-byte magic 0x13 "Freeway 5 Pro 5" at byte offset
/// 0x10 (16), so
/// the file begins 16 bytes before the magic. Header-only, no footer.
struct FreewaySignature;

const FREEWAY_MAGIC: &[u8] = &[
    0x13, b'F', b'r', b'e', b'e', b'w', b'a', b'y', b' ', b'5', b' ', b'P', b'r', b'o', b' ', b'5',
];
const FREEWAY_OFFSET: usize = 0x10;

impl FileSignature for FreewaySignature {
    fn name(&self) -> &str {
        "Freeway 5 Pro"
    }
    fn extensions(&self) -> &[&str] {
        &["freeway"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = FREEWAY_OFFSET + FREEWAY_MAGIC.len();
        if buf.len() >= end && &buf[FREEWAY_OFFSET..end] == FREEWAY_MAGIC {
            Some(RecoveryInit {
                min_filesize: 32,
                extension: "freeway".to_string(),
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
        FREEWAY_OFFSET as u16,
        FREEWAY_MAGIC,
        Arc::new(FreewaySignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freeway_header_match() {
        let sig = FreewaySignature;
        let mut buf = vec![0u8; FREEWAY_OFFSET];
        buf.extend_from_slice(FREEWAY_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_freeway_no_match() {
        let sig = FreewaySignature;
        // Magic present but at offset 0 instead of 0x10 -> no match.
        assert!(sig.header_check(FREEWAY_MAGIC, 0).is_none());
        assert!(sig.header_check(&[0u8; 32], 0).is_none());
    }
}
