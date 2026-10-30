use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adobe Custom Shapes carving signature. Header: "cush" 00 00 00 02 00 00 at offset 0 (10 bytes).
/// No footer, no encoded size.
const CSH_MAGIC: &[u8] = &[b'c', b'u', b's', b'h', 0x00, 0x00, 0x00, 0x02, 0x00, 0x00];

struct CshSignature;

impl FileSignature for CshSignature {
    fn name(&self) -> &str {
        "CSH"
    }
    fn extensions(&self) -> &[&str] {
        &["csh"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 10 && &buf[0..10] == CSH_MAGIC {
            Some(RecoveryInit {
                min_filesize: 10,
                extension: "csh".to_string(),
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
    registry.register(0, CSH_MAGIC, Arc::new(CshSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csh_header_match() {
        let mut buf = CSH_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 4]);
        assert!(CshSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_csh_no_match() {
        assert!(CshSignature
            .header_check(&[b'c', b'u', b's', b'h', 0, 0, 0, 0, 0, 0], 0)
            .is_none());
        assert!(CshSignature.header_check(b"XXXX", 0).is_none());
    }
}
