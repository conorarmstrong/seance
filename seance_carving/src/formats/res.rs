use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft Visual Studio Resource file carving signature. Header at offset 0: 14-byte magic 00 00
/// 00 00 20 00 00 00 FF FF 00 00 FF FF. No footer/size.
struct ResSignature;

const RES_MAGIC: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF,
];

impl FileSignature for ResSignature {
    fn name(&self) -> &str {
        "RES"
    }
    fn extensions(&self) -> &[&str] {
        &["res"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= RES_MAGIC.len() && &buf[0..RES_MAGIC.len()] == RES_MAGIC {
            Some(RecoveryInit {
                min_filesize: 14,
                extension: "res".to_string(),
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
    registry.register(0, RES_MAGIC, Arc::new(ResSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_res_header_match() {
        let sig = ResSignature;
        let mut buf = RES_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_res_no_match() {
        let sig = ResSignature;
        assert!(sig.header_check(b"NOTARESOURCE!!", 0).is_none());
        assert!(sig.header_check(b"\x00\x00", 0).is_none());
    }
}
