use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Windows prefetch (PF) carving signature. Header: 7-byte magic `00 00 00 'S' 'C' 'C' 'A'` at
/// offset 1 (byte 0 is the
/// varying version low byte). The LE uint32 at offset 12 encodes the exact file
/// size and must be at least the 84-byte header. No footer.
struct PfSignature;

const PF_MAGIC: [u8; 7] = [0x00, 0x00, 0x00, b'S', b'C', b'C', b'A'];

impl FileSignature for PfSignature {
    fn name(&self) -> &str {
        "PF"
    }
    fn extensions(&self) -> &[&str] {
        &["pf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 16 || buf[1..8] != PF_MAGIC {
            return None;
        }
        let size = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as u64;
        if size < 84 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 84,
            extension: "pf".to_string(),
            calculated_file_size: Some(size),
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
    // Magic located 1 byte into the file (byte 0 is the version low byte).
    registry.register(1, &PF_MAGIC, Arc::new(PfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pf_header_match() {
        let sig = PfSignature;
        let mut buf = [0u8; 16];
        buf[0] = 0x1e; // version low byte
        buf[1..8].copy_from_slice(&PF_MAGIC);
        buf[12..16].copy_from_slice(&200u32.to_le_bytes());
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(200));
    }

    #[test]
    fn test_pf_no_match() {
        let sig = PfSignature;
        // Wrong magic
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
        // Correct magic but size below header minimum
        let mut buf = [0u8; 16];
        buf[1..8].copy_from_slice(&PF_MAGIC);
        buf[12..16].copy_from_slice(&50u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
