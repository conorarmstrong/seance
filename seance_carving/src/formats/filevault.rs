use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FileVault encrypted disk image carving signature. Header: "encrcdsa" (8 bytes) at offset 0. No
/// footer/size.
struct FilevaultSignature;

const MAGIC: &[u8] = b"encrcdsa";

impl FileSignature for FilevaultSignature {
    fn name(&self) -> &str {
        "FileVault"
    }
    fn extensions(&self) -> &[&str] {
        &["sparseimage"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..8] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "sparseimage".to_string(),
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
    registry.register(0, MAGIC, Arc::new(FilevaultSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filevault_header_match() {
        let sig = FilevaultSignature;
        assert!(sig.header_check(b"encrcdsa\x00\x00", 0).is_some());
    }

    #[test]
    fn test_filevault_no_match() {
        let sig = FilevaultSignature;
        assert!(sig.header_check(b"encrcdsX", 0).is_none());
        assert!(sig.header_check(b"encr", 0).is_none());
    }
}
