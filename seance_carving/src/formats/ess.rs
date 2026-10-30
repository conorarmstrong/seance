use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Skyrim Savegame (ESS) carving signature. Header at offset 0: "TESV_SAVEGAME". No footer.
struct EssSignature;

impl FileSignature for EssSignature {
    fn name(&self) -> &str {
        "ESS"
    }
    fn extensions(&self) -> &[&str] {
        &["ess"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 13 && &buf[0..13] == b"TESV_SAVEGAME" {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "ess".to_string(),
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
    registry.register(0, b"TESV_SAVEGAME", Arc::new(EssSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ess_header_match() {
        let sig = EssSignature;
        assert!(sig.header_check(b"TESV_SAVEGAME\x00", 0).is_some());
    }

    #[test]
    fn test_ess_no_match() {
        let sig = EssSignature;
        assert!(sig.header_check(b"TESV_SAVEGAMX", 0).is_none());
        assert!(sig.header_check(b"TESV", 0).is_none());
    }
}
