use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Apple Logic EXS24 sampler instrument (.exs) carving signature.
/// Header (offset 0): 0x01 0x01 0x00 0x00 0x28 0x00 0x00 0x00, plus "TBOS" at offset 0x10.
struct ExsSignature;

const EXS_MAGIC: &[u8] = &[0x01, 0x01, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00];

impl FileSignature for ExsSignature {
    fn name(&self) -> &str {
        "EXS"
    }

    fn extensions(&self) -> &[&str] {
        &["exs"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x14 {
            return None;
        }
        if &buf[..EXS_MAGIC.len()] != EXS_MAGIC {
            return None;
        }
        if &buf[0x10..0x14] != b"TBOS" {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x14,
            extension: "exs".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, EXS_MAGIC, Arc::new(ExsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exs_header_match() {
        let sig = ExsSignature;
        let mut buf = vec![0u8; 0x14];
        buf[..8].copy_from_slice(EXS_MAGIC);
        buf[0x10..0x14].copy_from_slice(b"TBOS");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_exs_no_match() {
        let sig = ExsSignature;
        // Correct magic but missing TBOS marker.
        let mut buf = vec![0u8; 0x14];
        buf[..8].copy_from_slice(EXS_MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        let mut buf2 = vec![0u8; 0x14];
        buf2[0x10..0x14].copy_from_slice(b"TBOS");
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
