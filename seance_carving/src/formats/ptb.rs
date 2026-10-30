use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PowerTab carving signature. Header: "ptab" at offset 0, with a little-endian u16 version at
/// offset 4
/// that must be between 1 and 4. No footer; size not encoded.
struct PtbSignature;

impl FileSignature for PtbSignature {
    fn name(&self) -> &str {
        "PTB"
    }
    fn extensions(&self) -> &[&str] {
        &["ptb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 6 && &buf[0..4] == b"ptab" {
            let file_version = (buf[4] as u16) | ((buf[5] as u16) << 8);
            if (1..=4).contains(&file_version) {
                return Some(RecoveryInit {
                    min_filesize: 6,
                    extension: "ptb".to_string(),
                    calculated_file_size: None,
                });
            }
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        10 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"ptab", Arc::new(PtbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptb_header_match() {
        assert!(PtbSignature.header_check(b"ptab\x01\x00", 0).is_some());
        assert!(PtbSignature.header_check(b"ptab\x04\x00", 0).is_some());
    }

    #[test]
    fn test_ptb_no_match() {
        // Version 0 and version 5 are out of range.
        assert!(PtbSignature.header_check(b"ptab\x00\x00", 0).is_none());
        assert!(PtbSignature.header_check(b"ptab\x05\x00", 0).is_none());
        assert!(PtbSignature.header_check(b"NOPE\x01\x00", 0).is_none());
    }
}
