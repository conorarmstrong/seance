use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Windows Live Messenger log carving signature. Header at offset 0: "MSQMx" 0x00. No footer;
/// header check only.
const SQM_MAGIC: [u8; 6] = [b'M', b'S', b'Q', b'M', b'x', 0x00];

struct SqmSignature;

impl FileSignature for SqmSignature {
    fn name(&self) -> &str {
        "SQM"
    }
    fn extensions(&self) -> &[&str] {
        &["sqm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SQM_MAGIC.len() && buf[..SQM_MAGIC.len()] == SQM_MAGIC {
            Some(RecoveryInit {
                min_filesize: SQM_MAGIC.len() as u64,
                extension: "sqm".to_string(),
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
    registry.register(0, &SQM_MAGIC, Arc::new(SqmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqm_header_match() {
        let sig = SqmSignature;
        assert!(sig.header_check(b"MSQMx\x00rest", 0).is_some());
    }

    #[test]
    fn test_sqm_no_match() {
        let sig = SqmSignature;
        // Missing trailing NUL.
        assert!(sig.header_check(b"MSQMxA", 0).is_none());
        assert!(sig.header_check(b"NOTSQM", 0).is_none());
    }
}
