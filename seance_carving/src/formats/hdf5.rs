use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// HDF5 (Hierarchical Data Format 5) carving signature. Header: superblock signature 0x89 'H' 'D'
/// 'F' 0x0d 0x0a 0x1a 0x0a at offset 0,
/// followed by a superblock version byte (must be <= 2) at offset 8.
/// No footer; size bounded by max_file_size.
struct Hdf5Signature;

const HDF5_MAGIC: &[u8] = &[0x89, b'H', b'D', b'F', 0x0d, 0x0a, 0x1a, 0x0a];

impl FileSignature for Hdf5Signature {
    fn name(&self) -> &str {
        "HDF5"
    }
    fn extensions(&self) -> &[&str] {
        &["hdf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 9 && &buf[0..8] == HDF5_MAGIC && buf[8] <= 2 {
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "hdf".to_string(),
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
    registry.register(0, HDF5_MAGIC, Arc::new(Hdf5Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdf5_header_match() {
        let sig = Hdf5Signature;
        let buf = [0x89, b'H', b'D', b'F', 0x0d, 0x0a, 0x1a, 0x0a, 0x00];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_hdf5_no_match() {
        let sig = Hdf5Signature;
        // version > 2
        let bad_version = [0x89, b'H', b'D', b'F', 0x0d, 0x0a, 0x1a, 0x0a, 0x03];
        assert!(sig.header_check(&bad_version, 0).is_none());
        // wrong magic
        let bad_magic = [0x88, b'H', b'D', b'F', 0x0d, 0x0a, 0x1a, 0x0a, 0x00];
        assert!(sig.header_check(&bad_magic, 0).is_none());
        // too short
        assert!(sig.header_check(&[0x89, b'H', b'D', b'F'], 0).is_none());
    }
}
