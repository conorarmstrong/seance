use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Roxio Creator Global Image (.gi) carving signature. Header at offset 0: 12 magic bytes (da da fe
/// fe 00 06 1c 04 00 04 00 00), followed
/// by an le64 size at offset 12. The recovered file size is size + 20.
struct GiSignature;

const GI_MAGIC: &[u8] = &[
    0xda, 0xda, 0xfe, 0xfe, 0x00, 0x06, 0x1c, 0x04, 0x00, 0x04, 0x00, 0x00,
];

const GI_MAX: u64 = 8 * 1024 * 1024 * 1024;

impl FileSignature for GiSignature {
    fn name(&self) -> &str {
        "GI"
    }
    fn extensions(&self) -> &[&str] {
        &["gi"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 20 && &buf[0..12] == GI_MAGIC {
            let size = u64::from_le_bytes([
                buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
            ]);
            if size > GI_MAX {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "gi".to_string(),
                calculated_file_size: Some(size + 20),
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
        GI_MAX
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, GI_MAGIC, Arc::new(GiSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gi_header_match() {
        let sig = GiSignature;
        let mut buf = GI_MAGIC.to_vec();
        buf.extend_from_slice(&1000u64.to_le_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(1020));
    }

    #[test]
    fn test_gi_no_match() {
        let sig = GiSignature;
        // wrong magic
        let mut bad = vec![0x00u8; 12];
        bad.extend_from_slice(&1000u64.to_le_bytes());
        assert!(sig.header_check(&bad, 0).is_none());
        // size too large
        let mut big = GI_MAGIC.to_vec();
        big.extend_from_slice(&(GI_MAX + 1).to_le_bytes());
        assert!(sig.header_check(&big, 0).is_none());
    }
}
