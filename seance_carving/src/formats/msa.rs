use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Mensura (MSA) carving signature. Header: {0xfb,0xff,0xff,0xff} or {0xfc,0xff,0xff,0xff} at
/// offset 0, byte 0x13 == 0x40.
/// Size is the little-endian u32 at offset 4 (must exceed 0x13).
struct MsaSignature;

const MSA_MAGIC_FB: &[u8] = &[0xfb, 0xff, 0xff, 0xff];
const MSA_MAGIC_FC: &[u8] = &[0xfc, 0xff, 0xff, 0xff];

impl FileSignature for MsaSignature {
    fn name(&self) -> &str {
        "MSA"
    }

    fn extensions(&self) -> &[&str] {
        &["msa"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x14 {
            return None;
        }
        let magic_ok = (&buf[0..4] == MSA_MAGIC_FB) || (&buf[0..4] == MSA_MAGIC_FC);
        if !magic_ok || buf[0x13] != 0x40 {
            return None;
        }
        let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        if size <= 0x13 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x14,
            extension: "msa".to_string(),
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
    registry.register(0, MSA_MAGIC_FB, Arc::new(MsaSignature));
    registry.register(0, MSA_MAGIC_FC, Arc::new(MsaSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msa_header_match() {
        let sig = MsaSignature;
        let mut buf = vec![0u8; 0x14];
        buf[0..4].copy_from_slice(MSA_MAGIC_FB);
        buf[4] = 0x20; // size = 32, > 0x13
        buf[0x13] = 0x40;
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_msa_no_match() {
        let sig = MsaSignature;
        // Right magic and size but missing 0x40 marker.
        let mut buf = vec![0u8; 0x14];
        buf[0..4].copy_from_slice(MSA_MAGIC_FC);
        buf[4] = 0x20;
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let mut bad = vec![0u8; 0x14];
        bad[4] = 0x20;
        bad[0x13] = 0x40;
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
