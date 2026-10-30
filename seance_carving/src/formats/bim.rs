use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Broadcast Interface Module (BIM) carving signature. Header: 00 1F 01 '4' followed by
/// "urn:schemas-professionalDisc" (32 bytes total)
/// at offset 0. No footer or embedded size.
const BIM_MAGIC: &[u8] = &[
    0x00, 0x1f, 0x01, b'4', b'u', b'r', b'n', b':', b's', b'c', b'h', b'e', b'm', b'a', b's', b'-',
    b'p', b'r', b'o', b'f', b'e', b's', b's', b'i', b'o', b'n', b'a', b'l', b'D', b'i', b's', b'c',
];

struct BimSignature;

impl FileSignature for BimSignature {
    fn name(&self) -> &str {
        "BIM"
    }

    fn extensions(&self) -> &[&str] {
        &["bim"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= BIM_MAGIC.len() && &buf[0..BIM_MAGIC.len()] == BIM_MAGIC {
            Some(RecoveryInit {
                min_filesize: BIM_MAGIC.len() as u64,
                extension: "bim".to_string(),
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
    registry.register(0, BIM_MAGIC, Arc::new(BimSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bim_header_match() {
        let sig = BimSignature;
        let mut buf = BIM_MAGIC.to_vec();
        buf.extend_from_slice(b"trailing");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_bim_no_match() {
        let sig = BimSignature;
        assert!(sig
            .header_check(b"urn:schemas-professionalDisc", 0)
            .is_none());
        assert!(sig.header_check(b"\x00\x1f\x01\x33short", 0).is_none());
    }
}
