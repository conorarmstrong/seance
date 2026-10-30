use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// SketchUp carving signature. Header at offset 0: 0xff 0xfe 0xff 0x0e followed by "SketchUp Model"
/// encoded as UTF-16LE. No footer; header check only.
const SKP_MAGIC: [u8; 32] = [
    0xff, 0xfe, 0xff, 0x0e, b'S', 0x00, b'k', 0x00, b'e', 0x00, b't', 0x00, b'c', 0x00, b'h', 0x00,
    b'U', 0x00, b'p', 0x00, b' ', 0x00, b'M', 0x00, b'o', 0x00, b'd', 0x00, b'e', 0x00, b'l', 0x00,
];

struct SkpSignature;

impl FileSignature for SkpSignature {
    fn name(&self) -> &str {
        "SketchUp"
    }
    fn extensions(&self) -> &[&str] {
        &["skp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SKP_MAGIC.len() && buf[..SKP_MAGIC.len()] == SKP_MAGIC {
            Some(RecoveryInit {
                min_filesize: SKP_MAGIC.len() as u64,
                extension: "skp".to_string(),
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
    registry.register(0, &SKP_MAGIC, Arc::new(SkpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skp_header_match() {
        let sig = SkpSignature;
        let mut buf = SKP_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_skp_no_match() {
        let sig = SkpSignature;
        assert!(sig.header_check(b"NOTSKETCHUP", 0).is_none());
        // Correct first byte, wrong tail.
        let mut buf = SKP_MAGIC.to_vec();
        buf[4] = b'X';
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
