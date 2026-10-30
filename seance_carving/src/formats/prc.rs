use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PalmOS application (PRC) carving signature. Header: 12 zero bytes then "appl" (the `type` field)
/// at offset 0x30.
/// Additional check: big-endian uniqueIDSeed at 0x44 must be zero. No footer.
struct PrcSignature;

const PRC_MAGIC: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, b'a', b'p', b'p', b'l',
];

impl FileSignature for PrcSignature {
    fn name(&self) -> &str {
        "PRC"
    }

    fn extensions(&self) -> &[&str] {
        &["prc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic sits at 0x30; uniqueIDSeed (be32) is at 0x44 and must be zero.
        if buf.len() < 0x48 {
            return None;
        }
        if &buf[0x30..0x40] != PRC_MAGIC {
            return None;
        }
        if buf[0x44] != 0 || buf[0x45] != 0 || buf[0x46] != 0 || buf[0x47] != 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x48,
            extension: "prc".to_string(),
            calculated_file_size: None,
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
    registry.register(0x30, PRC_MAGIC, Arc::new(PrcSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prc_header_match() {
        let sig = PrcSignature;
        let mut buf = vec![0u8; 0x48];
        buf[0x3c..0x40].copy_from_slice(b"appl");
        // uniqueIDSeed at 0x44 left zero.
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_prc_no_match() {
        let sig = PrcSignature;
        let mut buf = vec![0u8; 0x48];
        buf[0x3c..0x40].copy_from_slice(b"appl");
        // Non-zero uniqueIDSeed.
        buf[0x44] = 1;
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
    }
}
