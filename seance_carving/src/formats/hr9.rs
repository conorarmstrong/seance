use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Heredis genealogy (HR9) carving signature. Header: 17-byte magic 0xc0 0xde 0xca 0xfe 0x00 0x00
/// 0x00 0x00 "Heredis" 0x99 0x20
/// at offset 0.
/// Note: PhotoRec sizes the file with file_search_footer looking for the 4-byte
/// footer 0xc0 0xde 0xca 0xfe (backward search, plus a 0x4c-byte trailer). That
/// footer is identical to the first four header bytes, so a forward data_check
/// scan would collide with the header; footer detection is degraded to a
/// header-only carve bounded by max_file_size.
struct Hr9Signature;

const HR9_MAGIC: &[u8] = &[
    0xc0, 0xde, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, b'H', b'e', b'r', b'e', b'd', b'i', b's', 0x99,
    0x20,
];

impl FileSignature for Hr9Signature {
    fn name(&self) -> &str {
        "Heredis"
    }
    fn extensions(&self) -> &[&str] {
        &["hr9"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 17 && &buf[0..17] == HR9_MAGIC {
            Some(RecoveryInit {
                min_filesize: 17,
                extension: "hr9".to_string(),
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
    registry.register(0, HR9_MAGIC, Arc::new(Hr9Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hr9_header_match() {
        let sig = Hr9Signature;
        assert!(sig.header_check(HR9_MAGIC, 0).is_some());
    }

    #[test]
    fn test_hr9_no_match() {
        let sig = Hr9Signature;
        // wrong byte in the "Heredis" portion
        let mut buf = HR9_MAGIC.to_vec();
        buf[8] = b'X';
        assert!(sig.header_check(&buf, 0).is_none());
        // too short
        assert!(sig.header_check(&[0xc0, 0xde, 0xca, 0xfe], 0).is_none());
    }
}
