use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Assassin's Creed II save file carving signature. Header at offset 8: UTF-16LE "ACII" (41 00 43
/// 00 49 00 49 00). No footer/size.
struct SaveSignature;

const SAVE_MAGIC: &[u8] = &[b'A', 0x00, b'C', 0x00, b'I', 0x00, b'I', 0x00];
const SAVE_OFFSET: usize = 8;

impl FileSignature for SaveSignature {
    fn name(&self) -> &str {
        "SAVE"
    }
    fn extensions(&self) -> &[&str] {
        &["save"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = SAVE_OFFSET + SAVE_MAGIC.len();
        if buf.len() >= end && &buf[SAVE_OFFSET..end] == SAVE_MAGIC {
            Some(RecoveryInit {
                min_filesize: end as u64,
                extension: "save".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(SAVE_OFFSET as u16, SAVE_MAGIC, Arc::new(SaveSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_header_match() {
        let sig = SaveSignature;
        // 8 leading bytes, then the UTF-16LE "ACII" magic at offset 8
        let mut buf = vec![0u8; SAVE_OFFSET];
        buf.extend_from_slice(SAVE_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_save_no_match() {
        let sig = SaveSignature;
        // Magic at wrong offset (0 instead of 8)
        let mut buf = SAVE_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short
        assert!(sig.header_check(b"short", 0).is_none());
    }
}
