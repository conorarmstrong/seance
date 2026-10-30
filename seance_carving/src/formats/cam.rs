use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Casio QV digital camera image (CAM) carving signature. Header: 07 20 'M' 'M'
/// (4 bytes) at offset 0. No footer or embedded size.
const CAM_MAGIC: &[u8] = &[0x07, 0x20, b'M', b'M'];

struct CamSignature;

impl FileSignature for CamSignature {
    fn name(&self) -> &str {
        "CAM"
    }

    fn extensions(&self) -> &[&str] {
        &["cam"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= CAM_MAGIC.len() && &buf[0..CAM_MAGIC.len()] == CAM_MAGIC {
            Some(RecoveryInit {
                min_filesize: CAM_MAGIC.len() as u64,
                extension: "cam".to_string(),
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
        10 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, CAM_MAGIC, Arc::new(CamSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cam_header_match() {
        let sig = CamSignature;
        assert!(sig
            .header_check(&[0x07, 0x20, b'M', b'M', 0x00, 0x01], 0)
            .is_some());
    }

    #[test]
    fn test_cam_no_match() {
        let sig = CamSignature;
        assert!(sig.header_check(&[0x07, 0x20, b'M', b'N'], 0).is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
