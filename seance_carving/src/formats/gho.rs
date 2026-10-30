use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Norton Ghost image carving signature. Header: 3-byte magic 0xfe 0xef 0x01 at offset 0, plus a
/// secondary check
/// that bytes 8..16 equal 01 01 00 00 00 00 00 00. Header-only, no footer.
struct GhoSignature;

const GHO_MAGIC: &[u8] = &[0xfe, 0xef, 0x01];
const GHO_NEXT: &[u8] = &[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

impl FileSignature for GhoSignature {
    fn name(&self) -> &str {
        "Ghost"
    }
    fn extensions(&self) -> &[&str] {
        &["gho"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 16 && &buf[0..3] == GHO_MAGIC && &buf[8..16] == GHO_NEXT {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "gho".to_string(),
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
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, GHO_MAGIC, Arc::new(GhoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gho_header_match() {
        let sig = GhoSignature;
        let buf = [
            0xfe, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_gho_no_match() {
        let sig = GhoSignature;
        // Correct primary magic but wrong secondary bytes.
        let buf = [
            0xfe, 0xef, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&[0xfe, 0xef, 0x01], 0).is_none());
    }
}
