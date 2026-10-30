use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Diablo II save (D2S) carving signature. Header: 55 AA 55 AA 60 00 00 00 at offset 0. The file
/// size is stored as a
/// little-endian u32 at offset 8. No footer.
struct D2sSignature;

const D2S_MAGIC: [u8; 8] = [0x55, 0xaa, 0x55, 0xaa, 0x60, 0x00, 0x00, 0x00];

impl FileSignature for D2sSignature {
    fn name(&self) -> &str {
        "D2S"
    }
    fn extensions(&self) -> &[&str] {
        &["d2s"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && buf[0..8] == D2S_MAGIC {
            let size = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
            // sizeof(struct d2s_header) == 20
            if (size as usize) < 20 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 20,
                extension: "d2s".to_string(),
                calculated_file_size: Some(size as u64),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &D2S_MAGIC, Arc::new(D2sSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_d2s_header_match() {
        let mut buf = D2S_MAGIC.to_vec();
        buf.extend_from_slice(&100u32.to_le_bytes());
        let init = D2sSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(100));
    }

    #[test]
    fn test_d2s_no_match() {
        // Wrong magic.
        let mut wrong = vec![0u8; 12];
        wrong[0] = 0x11;
        assert!(D2sSignature.header_check(&wrong, 0).is_none());
        // Correct magic but size below header size.
        let mut small = D2S_MAGIC.to_vec();
        small.extend_from_slice(&10u32.to_le_bytes());
        assert!(D2sSignature.header_check(&small, 0).is_none());
    }
}
