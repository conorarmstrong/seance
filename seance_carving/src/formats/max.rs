use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PaperPort MAX carving signature. Header: "ViGFk" at offset 0. No footer, no size in header.
struct MaxSignature;

const MAX_MAGIC: &[u8] = b"ViGFk";

impl FileSignature for MaxSignature {
    fn name(&self) -> &str {
        "MAX"
    }
    fn extensions(&self) -> &[&str] {
        &["max"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= MAX_MAGIC.len() && &buf[0..MAX_MAGIC.len()] == MAX_MAGIC {
            Some(RecoveryInit {
                min_filesize: 5,
                extension: "max".to_string(),
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
    registry.register(0, MAX_MAGIC, Arc::new(MaxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_header_match() {
        let sig = MaxSignature;
        assert!(sig.header_check(b"ViGFk\x00\x00", 0).is_some());
    }

    #[test]
    fn test_max_no_match() {
        let sig = MaxSignature;
        assert!(sig.header_check(b"ViGFx", 0).is_none());
        assert!(sig.header_check(b"NOT", 0).is_none());
    }
}
