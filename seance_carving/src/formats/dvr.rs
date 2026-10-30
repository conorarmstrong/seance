use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// RT60 DVR carving signature. Header at offset 0: "RT60", plus "XVID" required at offset 8.
/// min_filesize = 0x10. No footer.
struct DvrSignature;

impl FileSignature for DvrSignature {
    fn name(&self) -> &str {
        "DVR"
    }
    fn extensions(&self) -> &[&str] {
        &["dvr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..4] == b"RT60" && &buf[8..12] == b"XVID" {
            Some(RecoveryInit {
                min_filesize: 0x10,
                extension: "dvr".to_string(),
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
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"RT60", Arc::new(DvrSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dvr_header_match() {
        let sig = DvrSignature;
        assert!(sig.header_check(b"RT60\x00\x00\x00\x00XVID", 0).is_some());
    }

    #[test]
    fn test_dvr_no_match() {
        let sig = DvrSignature;
        // Missing XVID at offset 8
        assert!(sig.header_check(b"RT60\x00\x00\x00\x00AVID", 0).is_none());
        // Wrong header
        assert!(sig.header_check(b"RT61\x00\x00\x00\x00XVID", 0).is_none());
        // Too short
        assert!(sig.header_check(b"RT60", 0).is_none());
    }
}
