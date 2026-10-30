use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Acronis True Image (.tib) carving signature. Ported from file_tib.c.
/// Header variant 1: {0xb4,0x6e,0x68,0x44} at offset 0 (no footer logic).
/// Header variant 2: {0xce,0x24,0xb9,0xa2,0x20,0x00,0x00} at offset 0, whose PhotoRec
/// recovery scans 512-byte-aligned blocks for a trailing footer. That block-aligned
/// scan is stateful and is NOT ported here; both variants degrade to header + max-size.
struct TibSignature;

const TIB1: &[u8] = &[0xb4, 0x6e, 0x68, 0x44];
const TIB2: &[u8] = &[0xce, 0x24, 0xb9, 0xa2, 0x20, 0x00, 0x00];

impl FileSignature for TibSignature {
    fn name(&self) -> &str {
        "TIB"
    }

    fn extensions(&self) -> &[&str] {
        &["tib"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let matched = (buf.len() >= TIB1.len() && &buf[0..TIB1.len()] == TIB1)
            || (buf.len() >= TIB2.len() && &buf[0..TIB2.len()] == TIB2);
        if matched {
            Some(RecoveryInit {
                min_filesize: 512,
                extension: "tib".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn weak_header(&self) -> bool {
        // No public layout past the magic and no real sample is held, so the
        // magic alone must never split a running carve (CARVE-015).
        true
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, TIB1, Arc::new(TibSignature));
    registry.register(0, TIB2, Arc::new(TibSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tib_header_match() {
        let sig = TibSignature;
        assert!(sig.header_check(TIB1, 0).is_some());
        assert!(sig.header_check(TIB2, 0).is_some());
    }

    #[test]
    fn test_tib_no_match() {
        let sig = TibSignature;
        assert!(sig.header_check(&[0x00, 0x11, 0x22, 0x33], 0).is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
