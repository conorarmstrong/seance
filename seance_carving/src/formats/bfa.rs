use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Blowfish Advanced CS (.bfa) carving signature. Header: 8-byte magic at offset 0. The file size
/// is derived from the header:
/// lLength (u64 LE at offset 8) + wSizeOfHeader (u16 LE at offset 4).
struct BfaSignature;

/// 8-byte header magic.
const BFA_HEADER: [u8; 8] = [0x24, 0x08, 0x19, 0x92, 0x23, 0x00, 0x15, 0x01];

impl FileSignature for BfaSignature {
    fn name(&self) -> &str {
        "Blowfish Advanced CS"
    }

    fn extensions(&self) -> &[&str] {
        &["bfa"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 16 || buf[..BFA_HEADER.len()] != BFA_HEADER {
            return None;
        }
        let size_of_header = u16::from_le_bytes([buf[4], buf[5]]) as u64;
        let length = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let calculated = length.saturating_add(size_of_header);
        Some(RecoveryInit {
            min_filesize: 24, // sizeof(struct bfa_header)
            extension: "bfa".to_string(),
            calculated_file_size: Some(calculated),
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
    registry.register(0, &BFA_HEADER, Arc::new(BfaSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bfa_header_match() {
        let sig = BfaSignature;
        let mut buf = vec![0u8; 32];
        buf[..BFA_HEADER.len()].copy_from_slice(&BFA_HEADER);
        // wSizeOfHeader (bytes 4-5) is fixed at 0x0023 by the magic.
        buf[8..16].copy_from_slice(&0x1000u64.to_le_bytes()); // lLength
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x1000 + 0x0023));
    }

    #[test]
    fn test_bfa_no_match() {
        let sig = BfaSignature;
        let mut buf = vec![0u8; 32];
        buf[..BFA_HEADER.len()].copy_from_slice(&BFA_HEADER);
        buf[0] = 0x00; // corrupt magic
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&[0u8; 8], 0).is_none());
    }
}
