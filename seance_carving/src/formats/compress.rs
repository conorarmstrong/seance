use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MS compress (SZDD) carving signature. Header: "SZDD" 88 F0 27 33 'A' at offset 0 (9 bytes). No
/// footer, no encoded size.
const COMPRESS_MAGIC: &[u8] = &[b'S', b'Z', b'D', b'D', 0x88, 0xf0, 0x27, 0x33, b'A'];

struct CompressSignature;

impl FileSignature for CompressSignature {
    fn name(&self) -> &str {
        "SZDD"
    }
    fn extensions(&self) -> &[&str] {
        &["cp_"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 9 && &buf[0..9] == COMPRESS_MAGIC {
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "cp_".to_string(),
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
    registry.register(0, COMPRESS_MAGIC, Arc::new(CompressSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_header_match() {
        let mut buf = COMPRESS_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 4]);
        assert!(CompressSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_compress_no_match() {
        assert!(CompressSignature
            .header_check(&[b'S', b'Z', b'D', b'D', 0, 0, 0, 0, 0], 0)
            .is_none());
        assert!(CompressSignature.header_check(b"NOPE", 0).is_none());
    }
}
