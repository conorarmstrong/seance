use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WTV (Windows Media Center TV) carving signature. Header: 16-byte GUID {B7 D8 00 20 37 49 DA 11
/// A6 4E 00 07 E9 5E AD 8D} at offset 0.
/// File size = block count (u32 LE at 0x5c) << 12 (calculated_file_size); no footer.
/// Note: PhotoRec's continuation-block handling (header_ignored_adv) is not implemented.
struct WtvSignature;

const WTV_MAGIC: [u8; 16] = [
    0xb7, 0xd8, 0x00, b' ', b'7', b'I', 0xda, 0x11, 0xa6, b'N', 0x00, 0x07, 0xe9, 0x5e, 0xad, 0x8d,
];

impl FileSignature for WtvSignature {
    fn name(&self) -> &str {
        "WTV"
    }

    fn extensions(&self) -> &[&str] {
        &["wtv"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x60 || buf[0..16] != WTV_MAGIC {
            return None;
        }
        let block = u32::from_le_bytes([buf[0x5c], buf[0x5d], buf[0x5e], buf[0x5f]]);
        if block == 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x60,
            extension: "wtv".to_string(),
            calculated_file_size: Some((block as u64) << 12),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &WTV_MAGIC, Arc::new(WtvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wtv_header_match() {
        let mut buf = [0u8; 0x60];
        buf[0..16].copy_from_slice(&WTV_MAGIC);
        buf[0x5c] = 1; // block = 1 -> size 4096
        let sig = WtvSignature;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(4096));
    }

    #[test]
    fn test_wtv_no_match() {
        let sig = WtvSignature;
        let buf = [0u8; 0x60];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&WTV_MAGIC, 0).is_none());
    }
}
