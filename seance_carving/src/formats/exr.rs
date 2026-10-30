use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// OpenEXR image carving signature. Header at offset 0: 76 2f 31 01 02 ('v' 0x2f '1' 0x01 0x02).
/// min_filesize 0x20.
struct ExrSignature;

const EXR_MAGIC: &[u8] = &[0x76, 0x2f, 0x31, 0x01, 0x02];

impl FileSignature for ExrSignature {
    fn name(&self) -> &str {
        "EXR"
    }
    fn extensions(&self) -> &[&str] {
        &["exr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 5 && &buf[0..5] == EXR_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0x20,
                extension: "exr".to_string(),
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
    registry.register(0, EXR_MAGIC, Arc::new(ExrSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exr_header_match() {
        let sig = ExrSignature;
        assert!(sig
            .header_check(&[0x76, 0x2f, 0x31, 0x01, 0x02, 0x00], 0)
            .is_some());
    }

    #[test]
    fn test_exr_no_match() {
        let sig = ExrSignature;
        assert!(sig
            .header_check(&[0x76, 0x2f, 0x31, 0x01, 0x00], 0)
            .is_none());
        assert!(sig.header_check(&[0x76, 0x2f], 0).is_none());
    }
}
