use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// SafeHouse virtual disk carving signature. Header: 72-byte ASCII banner at offset 0 beginning
/// "WARNING: This file is a
/// SafeHouse virtual disk volume.\r\nheader version: ". min_filesize 0x1000. No footer.
struct SdskSignature;

const SDSK_MAGIC: &[u8] =
    b"WARNING: This file is a SafeHouse virtual disk volume.\r\nheader version: ";

impl FileSignature for SdskSignature {
    fn name(&self) -> &str {
        "SafeHouse virtual disk"
    }
    fn extensions(&self) -> &[&str] {
        &["sdsk"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SDSK_MAGIC.len() && &buf[0..SDSK_MAGIC.len()] == SDSK_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0x1000,
                extension: "sdsk".to_string(),
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
    registry.register(0, SDSK_MAGIC, Arc::new(SdskSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdsk_header_match() {
        let sig = SdskSignature;
        assert!(sig.header_check(SDSK_MAGIC, 0).is_some());
    }

    #[test]
    fn test_sdsk_no_match() {
        let sig = SdskSignature;
        assert!(sig
            .header_check(b"WARNING: not a safehouse volume at all here", 0)
            .is_none());
        assert!(sig.header_check(b"short", 0).is_none());
    }
}
