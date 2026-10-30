use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Personal Ancestral File carving signature. Header: "500\0500\0PAF" (11 bytes) at offset 0. No
/// footer, no size.
struct PafSignature;

const PAF_MAGIC: &[u8] = b"500\x00500\x00PAF";

impl FileSignature for PafSignature {
    fn name(&self) -> &str {
        "Personal Ancestral File"
    }
    fn extensions(&self) -> &[&str] {
        &["paf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= PAF_MAGIC.len() && &buf[0..PAF_MAGIC.len()] == PAF_MAGIC {
            Some(RecoveryInit {
                min_filesize: PAF_MAGIC.len() as u64,
                extension: "paf".to_string(),
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
    registry.register(0, PAF_MAGIC, Arc::new(PafSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paf_header_match() {
        let sig = PafSignature;
        assert!(sig.header_check(b"500\x00500\x00PAF\x00\x00", 0).is_some());
    }

    #[test]
    fn test_paf_no_match() {
        let sig = PafSignature;
        assert!(sig.header_check(b"500\x00500\x00XXX", 0).is_none());
        assert!(sig.header_check(b"500", 0).is_none());
    }
}
