use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// CATIA drawing (CATDrawing) carving signature. Header: 'V' '5' '_' 'C' 'F' 'V' '2' 00 00 (9
/// bytes) at offset 0. No footer or embedded size.
const CATDRAWING_MAGIC: &[u8] = &[b'V', b'5', b'_', b'C', b'F', b'V', b'2', 0x00, 0x00];

struct CatdrawingSignature;

impl FileSignature for CatdrawingSignature {
    fn name(&self) -> &str {
        "CATDRAWING"
    }

    fn extensions(&self) -> &[&str] {
        &["catdrawing"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= CATDRAWING_MAGIC.len()
            && &buf[0..CATDRAWING_MAGIC.len()] == CATDRAWING_MAGIC
        {
            Some(RecoveryInit {
                min_filesize: CATDRAWING_MAGIC.len() as u64,
                extension: "catdrawing".to_string(),
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
    registry.register(0, CATDRAWING_MAGIC, Arc::new(CatdrawingSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catdrawing_header_match() {
        let sig = CatdrawingSignature;
        let mut buf = CATDRAWING_MAGIC.to_vec();
        buf.extend_from_slice(b"payload");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_catdrawing_no_match() {
        let sig = CatdrawingSignature;
        assert!(sig
            .header_check(&[b'V', b'5', b'_', b'C', b'F', b'V', b'1', 0x00, 0x00], 0)
            .is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
