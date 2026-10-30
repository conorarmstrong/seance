use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PowerArchiver carving signature. Header: "PaFiLe\x00\x04" at offset 0. Size encoded as LE u64 at
/// offset 12;
/// calculated_file_size = 70 + size. No footer.
struct PaSignature;

// PhotoRec PHOTOREC_MAX_FILE_SIZE == (1<<41)-1 in the 64-bit build.
const PHOTOREC_MAX_FILE_SIZE: u64 = (1u64 << 41) - 1;

impl FileSignature for PaSignature {
    fn name(&self) -> &str {
        "PowerArchiver"
    }
    fn extensions(&self) -> &[&str] {
        &["pa"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need the 8-byte magic plus 4-byte unk plus 8-byte size field.
        if buf.len() >= 20 && &buf[0..8] == b"PaFiLe\x00\x04" {
            let size = u64::from_le_bytes(buf[12..20].try_into().unwrap());
            if size > PHOTOREC_MAX_FILE_SIZE {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 70,
                extension: "pa".to_string(),
                calculated_file_size: Some(70 + size),
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
    registry.register(0, b"PaFiLe\x00\x04", Arc::new(PaSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pa_header_match() {
        let sig = PaSignature;
        // magic + 4 unk bytes + LE u64 size == 100
        let mut buf = Vec::from(&b"PaFiLe\x00\x04"[..]);
        buf.extend_from_slice(&[0, 0, 0, 0]); // unk
        buf.extend_from_slice(&100u64.to_le_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(170));
    }

    #[test]
    fn test_pa_no_match() {
        let sig = PaSignature;
        let buf = [0u8; 20];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
