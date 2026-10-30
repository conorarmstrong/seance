use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// APA Style Helper carving signature. Header: "com.apa.Document" at offset 8 (16 bytes). No
/// footer; max-size cutoff.
struct ApaSignature;

const APA_MAGIC: &[u8] = b"com.apa.Document";
const APA_OFFSET: usize = 8;

impl FileSignature for ApaSignature {
    fn name(&self) -> &str {
        "APA"
    }
    fn extensions(&self) -> &[&str] {
        &["apa"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= APA_OFFSET + APA_MAGIC.len()
            && &buf[APA_OFFSET..APA_OFFSET + APA_MAGIC.len()] == APA_MAGIC
        {
            Some(RecoveryInit {
                min_filesize: (APA_OFFSET + APA_MAGIC.len()) as u64,
                extension: "apa".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(APA_OFFSET as u16, APA_MAGIC, Arc::new(ApaSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf() -> Vec<u8> {
        let mut buf = vec![0u8; APA_OFFSET + APA_MAGIC.len()];
        buf[APA_OFFSET..APA_OFFSET + APA_MAGIC.len()].copy_from_slice(APA_MAGIC);
        buf
    }

    #[test]
    fn test_apa_header_match() {
        let sig = ApaSignature;
        let buf = make_buf();
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_apa_no_match() {
        let sig = ApaSignature;
        // Corrupt magic.
        let mut buf = make_buf();
        buf[APA_OFFSET] = b'X';
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short.
        assert!(sig.header_check(b"com.apa", 0).is_none());
    }
}
