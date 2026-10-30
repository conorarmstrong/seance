use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Cinema 4D (C4D) carving signature. Header: "QC4DC4D6" (8 bytes) at offset 0. No footer or
/// embedded size.
struct C4dSignature;

impl FileSignature for C4dSignature {
    fn name(&self) -> &str {
        "C4D"
    }

    fn extensions(&self) -> &[&str] {
        &["c4d"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..8] == b"QC4DC4D6" {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "c4d".to_string(),
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
    registry.register(0, b"QC4DC4D6", Arc::new(C4dSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c4d_header_match() {
        let sig = C4dSignature;
        assert!(sig.header_check(b"QC4DC4D6payload", 0).is_some());
    }

    #[test]
    fn test_c4d_no_match() {
        let sig = C4dSignature;
        assert!(sig.header_check(b"QC4DC4D7", 0).is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
