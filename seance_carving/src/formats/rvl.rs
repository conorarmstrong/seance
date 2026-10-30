use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Revelation password file carving signature. Header at offset 0: "rvl" 00. Version byte (offset
/// 4) must be 1 or 2; bytes 5,9,10,11 must be 0.
/// No footer/size; min_filesize 28.
struct RvlSignature;

const RVL_MAGIC: &[u8] = &[b'r', b'v', b'l', 0x00];

impl FileSignature for RvlSignature {
    fn name(&self) -> &str {
        "RVL"
    }
    fn extensions(&self) -> &[&str] {
        &["rvl"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 || &buf[0..RVL_MAGIC.len()] != RVL_MAGIC {
            return None;
        }
        if buf[5] != 0 || buf[9] != 0 || buf[10] != 0 || buf[11] != 0 {
            return None;
        }
        // Recover version 1 and 2 only
        if buf[4] != 1 && buf[4] != 2 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 12 + 16,
            extension: "rvl".to_string(),
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
    registry.register(0, RVL_MAGIC, Arc::new(RvlSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rvl_header_match() {
        let sig = RvlSignature;
        // "rvl\0" + version=1 + byte5=0 + 3 bytes + bytes9,10,11 = 0
        let buf = [
            b'r', b'v', b'l', 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_rvl_no_match() {
        let sig = RvlSignature;
        // Wrong magic
        assert!(sig
            .header_check(b"Xvl\x00\x01\x00\x00\x00\x00\x00\x00\x00", 0)
            .is_none());
        // Bad version (3)
        let buf = [
            b'r', b'v', b'l', 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
