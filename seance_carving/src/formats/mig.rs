use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Windows Migration Backup carving signature. Header: magic {'1','g','i','M',0x02,0x00,0x00,0x00}
/// at offset 0, plus "MRTS" at 0x34.
/// PhotoRec's file_check walks STRM stream chunks to compute the size; that stateful
/// size calculation is not implemented (degraded to header magic + max size).
struct MigSignature;

const MIG_MAGIC: &[u8] = &[b'1', b'g', b'i', b'M', 0x02, 0x00, 0x00, 0x00];

impl FileSignature for MigSignature {
    fn name(&self) -> &str {
        "MIG"
    }

    fn extensions(&self) -> &[&str] {
        &["mig"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x38 && &buf[0..8] == MIG_MAGIC && &buf[0x34..0x38] == b"MRTS" {
            Some(RecoveryInit {
                min_filesize: 0x38,
                extension: "mig".to_string(),
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
    registry.register(0, MIG_MAGIC, Arc::new(MigSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mig_header_match() {
        let sig = MigSignature;
        let mut buf = vec![0u8; 0x38];
        buf[0..8].copy_from_slice(MIG_MAGIC);
        buf[0x34..0x38].copy_from_slice(b"MRTS");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_mig_no_match() {
        let sig = MigSignature;
        // Correct magic but no MRTS marker.
        let mut buf = vec![0u8; 0x38];
        buf[0..8].copy_from_slice(MIG_MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let bad = vec![0xAAu8; 0x38];
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
