use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ZoomBrowser thumbnail info carving signature. Header: fixed 20-byte magic starting with "zbex"
/// at offset 0.
/// No footer; header_check always accepts on magic match.
struct InfoSignature;

const INFO_MAGIC: &[u8] = &[
    b'z', b'b', b'e', b'x', 0x04, 0x00, 0x00, b'L', 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00,
];

impl FileSignature for InfoSignature {
    fn name(&self) -> &str {
        "INFO"
    }
    fn extensions(&self) -> &[&str] {
        &["info"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 20 && &buf[0..20] == INFO_MAGIC {
            Some(RecoveryInit {
                min_filesize: 20,
                extension: "info".to_string(),
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
    registry.register(0, INFO_MAGIC, Arc::new(InfoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_header_match() {
        let sig = InfoSignature;
        assert!(sig.header_check(INFO_MAGIC, 0).is_some());
    }

    #[test]
    fn test_info_no_match() {
        let sig = InfoSignature;
        assert!(sig.header_check(b"zbexWRONGDATAHERE1234", 0).is_none());
        assert!(sig.header_check(&[0u8; 8], 0).is_none());
    }
}
