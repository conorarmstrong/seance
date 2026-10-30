use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DAR archive carving signature. Header: 00 00 00 7B at offset 0. Additionally byte 0x0E is
/// 'N'/'T' and
/// byte 0x0F is 'N'/'S' (dar3 spec). No footer, no encoded size.
const DAR_MAGIC: &[u8] = &[0x00, 0x00, 0x00, 0x7b];

struct DarSignature;

impl FileSignature for DarSignature {
    fn name(&self) -> &str {
        "DAR"
    }
    fn extensions(&self) -> &[&str] {
        &["dar"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x10
            && &buf[0..4] == DAR_MAGIC
            && (buf[0x0e] == b'N' || buf[0x0e] == b'T')
            && (buf[0x0f] == b'N' || buf[0x0f] == b'S')
        {
            Some(RecoveryInit {
                min_filesize: 0x10,
                extension: "dar".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, DAR_MAGIC, Arc::new(DarSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dar_header_match() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(DAR_MAGIC);
        buf[0x0e] = b'N';
        buf[0x0f] = b'N';
        assert!(DarSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_dar_no_match() {
        // Correct leading magic but wrong trailing type bytes -> None
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(DAR_MAGIC);
        buf[0x0e] = b'X';
        buf[0x0f] = b'X';
        assert!(DarSignature.header_check(&buf, 0).is_none());
        // Wrong magic entirely
        assert!(DarSignature.header_check(&[0xff; 16], 0).is_none());
    }
}
