use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Football Manager save (FM) carving signature. Header: 02 01 "fmf." 07 00 00 (9 bytes) at offset
/// 0, then a
/// little-endian 64-bit size at offset 9; the file size is size + 12833.
/// No footer.
struct FmSignature;

const FM_MAGIC: &[u8] = &[0x02, 0x01, b'f', b'm', b'f', b'.', 0x07, 0x00, 0x00];

impl FileSignature for FmSignature {
    fn name(&self) -> &str {
        "FM"
    }
    fn extensions(&self) -> &[&str] {
        &["fm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 17 || &buf[0..9] != FM_MAGIC {
            return None;
        }
        let size = u64::from_le_bytes([
            buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16],
        ]);
        let calc = size.saturating_add(12833);
        Some(RecoveryInit {
            min_filesize: 0,
            extension: "fm".to_string(),
            calculated_file_size: Some(calc),
        })
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
    registry.register(0, FM_MAGIC, Arc::new(FmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fm_header_match() {
        let sig = FmSignature;
        let mut buf = FM_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // size = 4096
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(4096 + 12833));
    }

    #[test]
    fn test_fm_no_match() {
        let sig = FmSignature;
        assert!(sig.header_check(&[0u8; 17], 0).is_none());
        assert!(sig.header_check(b"WRONGMAGIC0000000", 0).is_none());
    }
}
