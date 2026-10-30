use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Contax picture RAW carving signature. Header: "ARECOYK" at offset 25. No footer; size not
/// encoded.
struct RawSignature;

impl FileSignature for RawSignature {
    fn name(&self) -> &str {
        "RAW"
    }
    fn extensions(&self) -> &[&str] {
        &["raw"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 32 && &buf[25..32] == b"ARECOYK" {
            Some(RecoveryInit {
                min_filesize: 32,
                extension: "raw".to_string(),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(25, b"ARECOYK", Arc::new(RawSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_header_match() {
        let mut buf = vec![0u8; 32];
        buf[25..32].copy_from_slice(b"ARECOYK");
        assert!(RawSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_raw_no_match() {
        let buf = vec![0u8; 32];
        assert!(RawSignature.header_check(&buf, 0).is_none());
        assert!(RawSignature.header_check(b"ARECOYK", 0).is_none());
    }
}
