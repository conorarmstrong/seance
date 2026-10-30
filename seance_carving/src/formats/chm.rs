use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// CHM carving signature. Header: "ITSF" 03 00 00 00 60 00 00 00 01 00 00 00 at offset 0 (16
/// bytes).
/// File size is encoded as a little-endian u32 at offset 104; must be >= 108.
const CHM_MAGIC: &[u8] = &[
    b'I', b'T', b'S', b'F', 0x03, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];

struct ChmSignature;

impl FileSignature for ChmSignature {
    fn name(&self) -> &str {
        "CHM"
    }
    fn extensions(&self) -> &[&str] {
        &["chm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 108 && &buf[0..16] == CHM_MAGIC {
            let size = (buf[104] as u64)
                | ((buf[105] as u64) << 8)
                | ((buf[106] as u64) << 16)
                | ((buf[107] as u64) << 24);
            if size < 108 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 108,
                extension: "chm".to_string(),
                calculated_file_size: Some(size),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, CHM_MAGIC, Arc::new(ChmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chm_header_match() {
        let mut buf = vec![0u8; 108];
        buf[0..16].copy_from_slice(CHM_MAGIC);
        // size = 200 (LE) at offset 104
        buf[104] = 200;
        let init = ChmSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(200));
    }

    #[test]
    fn test_chm_no_match() {
        let mut buf = vec![0u8; 108];
        buf[0..4].copy_from_slice(b"NOPE");
        assert!(ChmSignature.header_check(&buf, 0).is_none());
        // valid magic but size < 108 -> None
        let mut buf2 = vec![0u8; 108];
        buf2[0..16].copy_from_slice(CHM_MAGIC);
        buf2[104] = 10;
        assert!(ChmSignature.header_check(&buf2, 0).is_none());
    }
}
