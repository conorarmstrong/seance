use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// 1C:Enterprise 8 database (1CD) carving signature. Header at offset 0: "1CDBMSV8" 0x08. Size
/// (le32) at offset 12; the file size is
/// size << 12. Rejected when size == 0. No footer (size-based).
struct F1cdSignature;

const F1CD_MAGIC: &[u8] = &[b'1', b'C', b'D', b'B', b'M', b'S', b'V', b'8', 0x08];

impl FileSignature for F1cdSignature {
    fn name(&self) -> &str {
        "1CD"
    }
    fn extensions(&self) -> &[&str] {
        &["1cd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 16 && &buf[0..9] == F1CD_MAGIC {
            let size = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
            if size == 0 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "1cd".to_string(),
                calculated_file_size: Some((size as u64) << 12),
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
    registry.register(0, F1CD_MAGIC, Arc::new(F1cdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f1cd_header_match() {
        let sig = F1cdSignature;
        // magic (9 bytes) covers offset 0..9; version spans 8..12, size spans 12..16.
        let mut buf = F1CD_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // rest of version (offsets 9..12)
        buf.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // size = 2 (offsets 12..16)
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(2u64 << 12));
    }

    #[test]
    fn test_f1cd_no_match() {
        let sig = F1cdSignature;
        // size == 0 -> rejected
        let mut buf = F1CD_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00; 8]);
        assert!(sig.header_check(&buf, 0).is_none());
        // wrong magic
        let mut bad = vec![b'2', b'C', b'D', b'B', b'M', b'S', b'V', b'8', 0x08];
        bad.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
