use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Micrografx Designer (DRW) carving signature. Header: 0x01 0xff 0x02 0x04 0x03 0x02 0x00 0x02
/// 0x02 0x02 at offset 0. No footer.
struct Drw2Signature;

const DRW2_MAGIC: &[u8] = &[0x01, 0xff, 0x02, 0x04, 0x03, 0x02, 0x00, 0x02, 0x02, 0x02];

impl FileSignature for Drw2Signature {
    fn name(&self) -> &str {
        "DRW"
    }
    fn extensions(&self) -> &[&str] {
        &["drw"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= DRW2_MAGIC.len() && &buf[0..DRW2_MAGIC.len()] == DRW2_MAGIC {
            Some(RecoveryInit {
                min_filesize: DRW2_MAGIC.len() as u64,
                extension: "drw".to_string(),
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
    registry.register(0, DRW2_MAGIC, Arc::new(Drw2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drw2_header_match() {
        assert!(Drw2Signature.header_check(DRW2_MAGIC, 0).is_some());
    }

    #[test]
    fn test_drw2_no_match() {
        assert!(Drw2Signature.header_check(&[0u8; 10], 0).is_none());
        assert!(Drw2Signature.header_check(&[0x01, 0xff], 0).is_none());
    }
}
