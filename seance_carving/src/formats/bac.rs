use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Bacula backup (.bac) carving signature. Header: BlockNumber(0) + ID "BB02" at offset 8
/// (block_header). The BlockSize
/// field (big-endian u32 at offset 4) must be >= 0x18. PhotoRec's data_check
/// walks the "BB02" block chain; that stateful walk is degraded here to a
/// header-magic + min-size check (see note).
struct BacSignature;

/// 8-byte magic at offset 8: BlockNumber==0 then ID "BB02".
const BAC_HEADER: [u8; 8] = [0, 0, 0, 0, b'B', b'B', b'0', b'2'];

impl FileSignature for BacSignature {
    fn name(&self) -> &str {
        "Bacula backup"
    }

    fn extensions(&self) -> &[&str] {
        &["bac"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // BlockSize is a big-endian u32 at offset 4.
        if buf.len() < 8 {
            return None;
        }
        let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if block_size < 0x18 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: block_size as u64,
            extension: "bac".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(8, &BAC_HEADER, Arc::new(BacSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bac_header_match() {
        let sig = BacSignature;
        let mut buf = vec![0u8; 32];
        // BlockSize (big-endian) at offset 4 = 0x100 (>= 0x18)
        buf[4..8].copy_from_slice(&0x100u32.to_be_bytes());
        buf[8..16].copy_from_slice(&BAC_HEADER);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.min_filesize, 0x100);
    }

    #[test]
    fn test_bac_no_match() {
        let sig = BacSignature;
        let mut buf = vec![0u8; 32];
        // BlockSize < 0x18 rejects
        buf[4..8].copy_from_slice(&0x10u32.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&[0u8; 4], 0).is_none());
    }
}
