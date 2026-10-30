use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DB carving signature. Header: 19 01 00 08 02 20 at offset 0 (6 bytes). No footer, no encoded
/// size.
const DB_MAGIC: &[u8] = &[0x19, 0x01, 0x00, 0x08, 0x02, 0x20];

struct DbSignature;

impl FileSignature for DbSignature {
    fn name(&self) -> &str {
        "DB"
    }
    fn extensions(&self) -> &[&str] {
        &["DB"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 6 && &buf[0..6] == DB_MAGIC {
            Some(RecoveryInit {
                min_filesize: 6,
                extension: "DB".to_string(),
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
    registry.register(0, DB_MAGIC, Arc::new(DbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_header_match() {
        let buf = [0x19, 0x01, 0x00, 0x08, 0x02, 0x20, 0x00];
        assert!(DbSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_db_no_match() {
        assert!(DbSignature
            .header_check(&[0x19, 0x01, 0x00, 0x08, 0x02, 0x21], 0)
            .is_none());
        assert!(DbSignature.header_check(&[0x00, 0x00], 0).is_none());
    }
}
