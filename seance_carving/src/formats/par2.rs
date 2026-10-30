use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Parchive (PAR2) carving signature. Header: "PAR2\x00PKT" (8 bytes) at offset 0, followed by an
/// 8-byte
/// little-endian packet length at offset 8. PhotoRec walks packet lengths in a
/// stateful data_check; degraded here to a header check that validates the first
/// packet length and derives min_filesize (64 + length). No footer.
struct Par2Signature;

const PAR2_MAGIC: &[u8] = b"PAR2\x00PKT";
const PAR2_MAX_SIZE: u64 = 512 * 1024 * 1024;

impl FileSignature for Par2Signature {
    fn name(&self) -> &str {
        "PAR2"
    }

    fn extensions(&self) -> &[&str] {
        &["par2"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 16 || &buf[0..8] != PAR2_MAGIC {
            return None;
        }
        let length = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        if !length.is_multiple_of(4) || !(16..=PAR2_MAX_SIZE).contains(&length) {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 64 + length,
            extension: "par2".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        PAR2_MAX_SIZE
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, PAR2_MAGIC, Arc::new(Par2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_par2_header_match() {
        let sig = Par2Signature;
        // Magic + valid 8-byte length (0x40 = 64, multiple of 4, >= 16).
        let mut buf = Vec::from(PAR2_MAGIC);
        buf.extend_from_slice(&64u64.to_le_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.min_filesize, 64 + 64);
    }

    #[test]
    fn test_par2_no_match() {
        let sig = Par2Signature;
        // Wrong magic.
        let mut buf = Vec::from(&b"PAR2\x00XXX"[..]);
        buf.extend_from_slice(&64u64.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // Valid magic but invalid length (not a multiple of 4).
        let mut bad = Vec::from(PAR2_MAGIC);
        bad.extend_from_slice(&17u64.to_le_bytes());
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
