use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// iTunes library ("mhbd") carving signature. Header: "mhbd" + 0x68 00 00 00 (mhbd header size) at
/// offset 0. The total
/// file size is a little-endian u32 at offset 8 and must be >= 0x68; it is used
/// as the exact carved size (calculated_file_size).
struct ItuSignature;

const ITU_MAGIC: &[u8] = &[b'm', b'h', b'b', b'd', 0x68, 0x00, 0x00, 0x00];

impl FileSignature for ItuSignature {
    fn name(&self) -> &str {
        "ITU"
    }
    fn extensions(&self) -> &[&str] {
        &["itu"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 || &buf[0..8] != ITU_MAGIC {
            return None;
        }
        let size = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
        if size < 0x68 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x68,
            extension: "itu".to_string(),
            calculated_file_size: Some(size),
        })
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
    registry.register(0, ITU_MAGIC, Arc::new(ItuSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_itu_header_match() {
        let sig = ItuSignature;
        let mut buf = Vec::new();
        buf.extend_from_slice(ITU_MAGIC);
        buf.extend_from_slice(&0x68u32.to_le_bytes());
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(0x68));
    }

    #[test]
    fn test_itu_no_match() {
        let sig = ItuSignature;
        // Size below minimum 0x68.
        let mut buf = Vec::new();
        buf.extend_from_slice(ITU_MAGIC);
        buf.extend_from_slice(&0x10u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(&[0u8; 12], 0).is_none());
    }
}
