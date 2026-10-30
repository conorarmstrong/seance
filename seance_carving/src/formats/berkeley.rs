use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Berkeley DB (little-endian) carving signature. Header: hash (0x00061561) or btree (0x00053162)
/// magic followed by version 8 or 9,
/// located at offset 0xC. No footer or embedded size.
struct BerkeleySignature;

/// The four enabled magic variants (hash v8/v9, btree v8/v9), each at offset 0xC.
const BDB_HASH_8: [u8; 8] = [0x61, 0x15, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00];
const BDB_HASH_9: [u8; 8] = [0x61, 0x15, 0x06, 0x00, 0x09, 0x00, 0x00, 0x00];
const BDB_BTREE_8: [u8; 8] = [0x62, 0x31, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00];
const BDB_BTREE_9: [u8; 8] = [0x62, 0x31, 0x05, 0x00, 0x09, 0x00, 0x00, 0x00];

impl FileSignature for BerkeleySignature {
    fn name(&self) -> &str {
        "Berkeley DB"
    }

    fn extensions(&self) -> &[&str] {
        &["db"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0xC + 8 {
            return None;
        }
        let m = &buf[0xC..0xC + 8];
        if *m == BDB_HASH_8 || *m == BDB_HASH_9 || *m == BDB_BTREE_8 || *m == BDB_BTREE_9 {
            Some(RecoveryInit {
                min_filesize: 0xC + 8,
                extension: "db".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0xC, &BDB_HASH_8, Arc::new(BerkeleySignature));
    registry.register(0xC, &BDB_HASH_9, Arc::new(BerkeleySignature));
    registry.register(0xC, &BDB_BTREE_8, Arc::new(BerkeleySignature));
    registry.register(0xC, &BDB_BTREE_9, Arc::new(BerkeleySignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_berkeley_header_match() {
        let sig = BerkeleySignature;
        let mut buf = vec![0u8; 32];
        buf[0xC..0xC + 8].copy_from_slice(&BDB_HASH_8);
        assert!(sig.header_check(&buf, 0).is_some());
        buf[0xC..0xC + 8].copy_from_slice(&BDB_BTREE_9);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_berkeley_no_match() {
        let sig = BerkeleySignature;
        let buf = vec![0u8; 32];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&[0u8; 4], 0).is_none());
    }
}
