use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// StuffIt archive carving signature. Header at offset 0: "StuffIt". No footer; header check only.
const STU_MAGIC: &[u8] = b"StuffIt";

struct StuSignature;

impl FileSignature for StuSignature {
    fn name(&self) -> &str {
        "StuffIt"
    }
    fn extensions(&self) -> &[&str] {
        &["sit"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= STU_MAGIC.len() && &buf[..STU_MAGIC.len()] == STU_MAGIC {
            Some(RecoveryInit {
                min_filesize: STU_MAGIC.len() as u64,
                extension: "sit".to_string(),
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
    registry.register(0, STU_MAGIC, Arc::new(StuSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stu_header_match() {
        let sig = StuSignature;
        assert!(sig.header_check(b"StuffIt (c)1997", 0).is_some());
    }

    #[test]
    fn test_stu_no_match() {
        let sig = StuSignature;
        assert!(sig.header_check(b"StuffXt", 0).is_none());
        assert!(sig.header_check(b"NOTSIT", 0).is_none());
    }
}
