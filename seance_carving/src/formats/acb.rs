use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adobe Color Book carving signature. Header: "8BCB" 0x00 0x01 0x0b at offset 0 (7 bytes). No
/// footer; max-size cutoff.
struct AcbSignature;

const ACB_MAGIC: &[u8] = &[b'8', b'B', b'C', b'B', 0x00, 0x01, 0x0b];

impl FileSignature for AcbSignature {
    fn name(&self) -> &str {
        "ACB"
    }
    fn extensions(&self) -> &[&str] {
        &["acb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= ACB_MAGIC.len() && &buf[0..ACB_MAGIC.len()] == ACB_MAGIC {
            Some(RecoveryInit {
                min_filesize: 7,
                extension: "acb".to_string(),
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
    registry.register(0, ACB_MAGIC, Arc::new(AcbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acb_header_match() {
        let sig = AcbSignature;
        let mut buf = ACB_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_acb_no_match() {
        let sig = AcbSignature;
        // Wrong third magic byte.
        assert!(sig
            .header_check(&[b'8', b'B', b'X', b'B', 0x00, 0x01, 0x0b], 0)
            .is_none());
        // Too short.
        assert!(sig.header_check(b"8BC", 0).is_none());
    }
}
