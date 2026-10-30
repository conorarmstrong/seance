use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Cubase Song file (.all) carving signature. Header: 00 00 00 48 00 00 06 04 at offset 0 (8
/// bytes). min_filesize 122.
/// No footer; max-size cutoff.
struct AllSignature;

const ALL_MAGIC: &[u8] = &[0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x06, 0x04];

impl FileSignature for AllSignature {
    fn name(&self) -> &str {
        "ALL"
    }
    fn extensions(&self) -> &[&str] {
        &["all"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= ALL_MAGIC.len() && &buf[0..ALL_MAGIC.len()] == ALL_MAGIC {
            Some(RecoveryInit {
                min_filesize: 122,
                extension: "all".to_string(),
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
        50 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, ALL_MAGIC, Arc::new(AllSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_header_match() {
        let sig = AllSignature;
        let mut buf = ALL_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 16]);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.min_filesize, 122);
    }

    #[test]
    fn test_all_no_match() {
        let sig = AllSignature;
        // Wrong fourth byte.
        assert!(sig
            .header_check(&[0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x06, 0x04], 0)
            .is_none());
        // Too short.
        assert!(sig.header_check(&[0x00, 0x00, 0x00], 0).is_none());
    }
}
