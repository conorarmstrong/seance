use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WOFF (Web Open Font Format) carving signature. Header: "wOFF" (0x77 0x4F 0x46 0x46) at offset 0.
/// File size is the big-endian `length` field (calculated_file_size); no footer.
struct WoffSignature;

impl FileSignature for WoffSignature {
    fn name(&self) -> &str {
        "WOFF"
    }

    fn extensions(&self) -> &[&str] {
        &["woff"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // sizeof(struct WOFFHeader) == 44
        if buf.len() < 44 || &buf[0..4] != b"wOFF" {
            return None;
        }
        let length = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let reserved = u16::from_be_bytes([buf[14], buf[15]]);
        let meta_offset = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let meta_length = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let priv_offset = u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let priv_length = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
        if length < 44 {
            return None;
        }
        if meta_offset > 0 && meta_offset < 44 {
            return None;
        }
        if priv_offset > 0 && priv_offset < 44 {
            return None;
        }
        if meta_offset as u64 + meta_length as u64 > length as u64
            || priv_offset as u64 + priv_length as u64 > length as u64
        {
            return None;
        }
        if reserved != 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 44,
            extension: "woff".to_string(),
            calculated_file_size: Some(length as u64),
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
    registry.register(0, b"wOFF", Arc::new(WoffSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_woff_header_match() {
        let mut buf = [0u8; 44];
        buf[0..4].copy_from_slice(b"wOFF");
        // length = 44 (big-endian)
        buf[8..12].copy_from_slice(&44u32.to_be_bytes());
        let sig = WoffSignature;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(44));
    }

    #[test]
    fn test_woff_no_match() {
        let sig = WoffSignature;
        let mut buf = [0u8; 44];
        buf[0..4].copy_from_slice(b"wOTF");
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"wOFF", 0).is_none());
    }
}
