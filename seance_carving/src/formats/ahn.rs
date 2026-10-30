use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Ahnenblatt carving signature. Header: "dbf" 0x00 at offset 0 and "AHNENBLATT" at offset 8. No
/// footer;
/// max-size cutoff.
struct AhnSignature;

const AHN_PREFIX: &[u8] = &[b'd', b'b', b'f', 0x00];
const AHN_MAGIC: &[u8] = b"AHNENBLATT";
const AHN_OFFSET: usize = 8;

impl FileSignature for AhnSignature {
    fn name(&self) -> &str {
        "AHN"
    }
    fn extensions(&self) -> &[&str] {
        &["ahn"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= AHN_OFFSET + AHN_MAGIC.len()
            && &buf[0..AHN_PREFIX.len()] == AHN_PREFIX
            && &buf[AHN_OFFSET..AHN_OFFSET + AHN_MAGIC.len()] == AHN_MAGIC
        {
            Some(RecoveryInit {
                min_filesize: (AHN_OFFSET + AHN_MAGIC.len()) as u64,
                extension: "ahn".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(AHN_OFFSET as u16, AHN_MAGIC, Arc::new(AhnSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf() -> Vec<u8> {
        let mut buf = vec![0u8; AHN_OFFSET + AHN_MAGIC.len()];
        buf[0..AHN_PREFIX.len()].copy_from_slice(AHN_PREFIX);
        buf[AHN_OFFSET..AHN_OFFSET + AHN_MAGIC.len()].copy_from_slice(AHN_MAGIC);
        buf
    }

    #[test]
    fn test_ahn_header_match() {
        let sig = AhnSignature;
        let buf = make_buf();
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_ahn_no_match() {
        let sig = AhnSignature;
        // Wrong prefix.
        let mut buf = make_buf();
        buf[0] = b'x';
        assert!(sig.header_check(&buf, 0).is_none());
        // Missing AHNENBLATT magic.
        let mut buf2 = make_buf();
        buf2[AHN_OFFSET] = 0x00;
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
