use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft Cabinet archive carving signature. Header: "MSCF" at offset 0. cab_version (le16 @24)
/// must be 0x0103 and
/// filesize (le32 @8) >= 36 (struct cab_header size). Exact size from header.
struct CabSignature;

impl FileSignature for CabSignature {
    fn name(&self) -> &str {
        "Microsoft Cabinet"
    }
    fn extensions(&self) -> &[&str] {
        &["cab"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct cab_header is 36 bytes.
        if buf.len() >= 36 && &buf[0..4] == b"MSCF" {
            let filesize = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
            let cab_version = u16::from_le_bytes([buf[24], buf[25]]);
            if cab_version == 0x0103 && filesize >= 36 {
                return Some(RecoveryInit {
                    min_filesize: 36,
                    extension: "cab".to_string(),
                    calculated_file_size: Some(filesize as u64),
                });
            }
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"MSCF", Arc::new(CabSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        buf[0..4].copy_from_slice(b"MSCF");
        buf[8..12].copy_from_slice(&100u32.to_le_bytes()); // filesize
        buf[24] = 0x03; // cab_version le16 = 0x0103
        buf[25] = 0x01;
        buf
    }

    #[test]
    fn test_cab_header_match() {
        let sig = CabSignature;
        assert!(sig.header_check(&valid_buf(), 0).is_some());
    }

    #[test]
    fn test_cab_no_match() {
        let sig = CabSignature;
        // Wrong magic.
        let mut bad = valid_buf();
        bad[0] = b'X';
        assert!(sig.header_check(&bad, 0).is_none());
        // Wrong cab_version.
        let mut bad2 = valid_buf();
        bad2[24] = 0x00;
        assert!(sig.header_check(&bad2, 0).is_none());
    }
}
