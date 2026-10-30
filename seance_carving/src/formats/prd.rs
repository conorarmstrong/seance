use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Paessler PRTG carving signature. Header: 8-byte magic {0x01,0x00,...,0x00} at offset 0, plus
/// fixed bytes
/// 0xDB 0xE4 0x40 at offsets 0x0D and 0x15. No footer; size not encoded.
struct PrdSignature;

impl FileSignature for PrdSignature {
    fn name(&self) -> &str {
        "PRD"
    }
    fn extensions(&self) -> &[&str] {
        &["prd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x18
            && buf[0] == 0x01
            && buf[1] == 0x00
            && buf[2] == 0x00
            && buf[3] == 0x00
            && buf[4] == 0x00
            && buf[5] == 0x00
            && buf[6] == 0x00
            && buf[7] == 0x00
            && buf[0x0d] == 0xdb
            && buf[0x0e] == 0xe4
            && buf[0x0f] == 0x40
            && buf[0x15] == 0xdb
            && buf[0x16] == 0xe4
            && buf[0x17] == 0x40
        {
            Some(RecoveryInit {
                min_filesize: 0x18,
                extension: "prd".to_string(),
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
    registry.register(
        0,
        &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        Arc::new(PrdSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prd_header_match() {
        let mut buf = vec![0u8; 0x18];
        buf[0] = 0x01;
        buf[0x0d] = 0xdb;
        buf[0x0e] = 0xe4;
        buf[0x0f] = 0x40;
        buf[0x15] = 0xdb;
        buf[0x16] = 0xe4;
        buf[0x17] = 0x40;
        assert!(PrdSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_prd_no_match() {
        let mut buf = vec![0u8; 0x18];
        buf[0] = 0x01;
        // Missing the 0xDB 0xE4 0x40 markers.
        assert!(PrdSignature.header_check(&buf, 0).is_none());
        assert!(PrdSignature.header_check(b"short", 0).is_none());
    }
}
