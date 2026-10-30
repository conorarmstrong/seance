use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Wink presentation carving signature. Header: "RPKWI" 0x02 at offset 0. No footer; size not
/// encoded.
struct WnkSignature;

const WNK_MAGIC: &[u8] = &[b'R', b'P', b'K', b'W', b'I', 0x02];

impl FileSignature for WnkSignature {
    fn name(&self) -> &str {
        "WNK"
    }
    fn extensions(&self) -> &[&str] {
        &["wnk"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= WNK_MAGIC.len() && &buf[0..WNK_MAGIC.len()] == WNK_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "wnk".to_string(),
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
    registry.register(0, WNK_MAGIC, Arc::new(WnkSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wnk_header_match() {
        assert!(WnkSignature.header_check(WNK_MAGIC, 0).is_some());
    }

    #[test]
    fn test_wnk_no_match() {
        assert!(WnkSignature.header_check(b"RPKWI\x03", 0).is_none());
        assert!(WnkSignature.header_check(b"RPKW", 0).is_none());
    }
}
