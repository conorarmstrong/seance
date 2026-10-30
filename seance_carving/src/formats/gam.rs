use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Games Factory carving signature. Header: 6-byte magic "GAPP" 0x07 0x02 at offset 0. Header-only,
/// no footer.
struct GamSignature;

const GAM_MAGIC: &[u8] = &[b'G', b'A', b'P', b'P', 0x07, 0x02];

impl FileSignature for GamSignature {
    fn name(&self) -> &str {
        "Games Factory"
    }
    fn extensions(&self) -> &[&str] {
        &["gam"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= GAM_MAGIC.len() && &buf[0..GAM_MAGIC.len()] == GAM_MAGIC {
            Some(RecoveryInit {
                min_filesize: 6,
                extension: "gam".to_string(),
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
    registry.register(0, GAM_MAGIC, Arc::new(GamSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gam_header_match() {
        let sig = GamSignature;
        assert!(sig
            .header_check(&[b'G', b'A', b'P', b'P', 0x07, 0x02, 0x00], 0)
            .is_some());
    }

    #[test]
    fn test_gam_no_match() {
        let sig = GamSignature;
        assert!(sig
            .header_check(&[b'G', b'A', b'P', b'P', 0x00, 0x00], 0)
            .is_none());
        assert!(sig.header_check(b"GAP", 0).is_none());
    }
}
