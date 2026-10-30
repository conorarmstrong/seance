use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ShadowProtect image carving signature. Header: "SPFI" 0x00 0x02 0x00 0x00 0x41 0x00 0x00 0x00
/// (12 bytes) at offset 0.
/// NOTE: PhotoRec's file_check_spf walks the file in 512-byte sectors and stops
/// at the first sector that is zero past its first 8 bytes. That stateful
/// end-of-file scan is not implemented here; this is a faithful header-magic +
/// max-size signature.
struct SpfSignature;

const SPF_MAGIC: &[u8] = &[
    b'S', b'P', b'F', b'I', 0x00, 0x02, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
];

impl FileSignature for SpfSignature {
    fn name(&self) -> &str {
        "ShadowProtect"
    }
    fn extensions(&self) -> &[&str] {
        &["spf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..12] == SPF_MAGIC {
            Some(RecoveryInit {
                min_filesize: 512,
                extension: "spf".to_string(),
                calculated_file_size: None,
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
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, SPF_MAGIC, Arc::new(SpfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spf_header_match() {
        let sig = SpfSignature;
        assert!(sig.header_check(SPF_MAGIC, 0).is_some());
    }

    #[test]
    fn test_spf_no_match() {
        let sig = SpfSignature;
        // wrong byte in magic
        let mut bad = SPF_MAGIC.to_vec();
        bad[5] = 0x03;
        assert!(sig.header_check(&bad, 0).is_none());
        // too short
        assert!(sig.header_check(b"SPFI", 0).is_none());
    }
}
