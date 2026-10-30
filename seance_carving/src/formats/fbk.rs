use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft Dynamics NAV (Navision) backup carving signature. Header: "TableData " (10 bytes) at
/// offset 0. No footer/size.
struct FbkSignature;

const MAGIC: &[u8] = b"TableData ";

impl FileSignature for FbkSignature {
    fn name(&self) -> &str {
        "MS Dynamics NAV Backup"
    }
    fn extensions(&self) -> &[&str] {
        &["fbk"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 10 && &buf[0..10] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 10,
                extension: "fbk".to_string(),
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
    registry.register(0, MAGIC, Arc::new(FbkSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fbk_header_match() {
        let sig = FbkSignature;
        assert!(sig.header_check(b"TableData \x00\x00", 0).is_some());
    }

    #[test]
    fn test_fbk_no_match() {
        let sig = FbkSignature;
        assert!(sig.header_check(b"TableDatX ", 0).is_none());
        assert!(sig.header_check(b"Table", 0).is_none());
    }
}
