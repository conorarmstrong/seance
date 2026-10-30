use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Incredimail carving signature. Header: 15-byte magic {00 00 00 "Incredimail "} registered at
/// offset 1
/// (so the file begins one byte before the magic). No footer; min size 16.
struct ImbSignature;

const IMB_MAGIC: &[u8] = &[
    0x00, 0x00, 0x00, b'I', b'n', b'c', b'r', b'e', b'd', b'i', b'm', b'a', b'i', b'l', b' ',
];

impl FileSignature for ImbSignature {
    fn name(&self) -> &str {
        "IMB"
    }
    fn extensions(&self) -> &[&str] {
        &["imb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Registered at offset 1: the magic starts one byte into the file.
        if buf.len() >= 16 && &buf[1..16] == IMB_MAGIC {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "imb".to_string(),
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
    registry.register(1, IMB_MAGIC, Arc::new(ImbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imb_header_match() {
        let sig = ImbSignature;
        let mut buf = vec![0x55u8]; // arbitrary leading byte at offset 0
        buf.extend_from_slice(IMB_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_imb_no_match() {
        let sig = ImbSignature;
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
        assert!(sig.header_check(b"short", 0).is_none());
    }
}
