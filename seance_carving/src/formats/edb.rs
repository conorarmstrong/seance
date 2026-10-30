use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Exchange Database (EDB) carving signature. Magic at offset 4: ef cd ab 89 20 06 00 00. No
/// footer.
struct EdbSignature;

const EDB_MAGIC: &[u8] = &[0xef, 0xcd, 0xab, 0x89, 0x20, 0x06, 0x00, 0x00];

impl FileSignature for EdbSignature {
    fn name(&self) -> &str {
        "EDB"
    }
    fn extensions(&self) -> &[&str] {
        &["edb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[4..12] == EDB_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "edb".to_string(),
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
    registry.register(4, EDB_MAGIC, Arc::new(EdbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edb_header_match() {
        let sig = EdbSignature;
        let mut buf = vec![0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(EDB_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_edb_no_match() {
        let sig = EdbSignature;
        let mut buf = vec![0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&[0xef, 0xcd, 0xab, 0x89, 0x20, 0x07, 0x00, 0x00]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short
        assert!(sig.header_check(&[0x00; 8], 0).is_none());
    }
}
