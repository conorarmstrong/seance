use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// OpenCanvas painting document carving signature. Header: "WPB2" 0x00 0x00 0x00 0x00 at offset 0.
/// No footer; size not encoded.
struct WpbSignature;

const WPB_MAGIC: &[u8] = b"WPB2\x00\x00\x00\x00";

impl FileSignature for WpbSignature {
    fn name(&self) -> &str {
        "WPB"
    }
    fn extensions(&self) -> &[&str] {
        &["wpb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= WPB_MAGIC.len() && &buf[0..WPB_MAGIC.len()] == WPB_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "wpb".to_string(),
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
    registry.register(0, WPB_MAGIC, Arc::new(WpbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wpb_header_match() {
        assert!(WpbSignature.header_check(WPB_MAGIC, 0).is_some());
    }

    #[test]
    fn test_wpb_no_match() {
        assert!(WpbSignature
            .header_check(b"WPB1\x00\x00\x00\x00", 0)
            .is_none());
        assert!(WpbSignature.header_check(b"WPB2", 0).is_none());
    }
}
