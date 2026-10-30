use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft Dynamics NAV (Navision) database carving signature. Header: 00 00 00 5c a0 83 02 (7
/// bytes) at offset 5. No footer/size.
struct FdbSignature;

const MAGIC: [u8; 7] = [0x00, 0x00, 0x00, 0x5c, 0xa0, 0x83, 0x02];

impl FileSignature for FdbSignature {
    fn name(&self) -> &str {
        "MS Dynamics NAV DB"
    }
    fn extensions(&self) -> &[&str] {
        &["fdb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic is located 5 bytes into the file.
        if buf.len() >= 12 && buf[5..12] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 12,
                extension: "fdb".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(5, &MAGIC, Arc::new(FdbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fdb_header_match() {
        let sig = FdbSignature;
        let mut buf = vec![0xFFu8; 12];
        buf[5..12].copy_from_slice(&MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_fdb_no_match() {
        let sig = FdbSignature;
        let buf = vec![0u8; 12];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&[0u8; 6], 0).is_none());
    }
}
