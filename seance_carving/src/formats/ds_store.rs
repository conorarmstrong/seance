use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Apple Desktop Services Store (.DS_Store) carving signature.
/// Header: {0x00,0x00,0x00,0x01,'B','u','d','1'} at offset 0. The two 32-bit
/// offset fields at bytes 8 and 16 must be equal; minimum size is derived as
/// big-endian offset + big-endian size (bytes 8 and 12).
struct DsStoreSignature;

impl FileSignature for DsStoreSignature {
    fn name(&self) -> &str {
        "DS_Store"
    }

    fn extensions(&self) -> &[&str] {
        &["DS_Store"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 20 {
            return None;
        }
        // offset (bytes 8..12) must equal offset2 (bytes 16..20).
        if buf[8..12] != buf[16..20] {
            return None;
        }
        let offset = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
        let size = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]) as u64;
        Some(RecoveryInit {
            min_filesize: offset + size,
            extension: "DS_Store".to_string(),
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
    registry.register(
        0,
        &[0x00, 0x00, 0x00, 0x01, b'B', b'u', b'd', b'1'],
        Arc::new(DsStoreSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(offset: u32, size: u32, offset2: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x01, b'B', b'u', b'd', b'1']);
        buf[8..12].copy_from_slice(&offset.to_be_bytes());
        buf[12..16].copy_from_slice(&size.to_be_bytes());
        buf[16..20].copy_from_slice(&offset2.to_be_bytes());
        buf
    }

    #[test]
    fn test_ds_store_header_match() {
        let sig = DsStoreSignature;
        let buf = make_header(0x800, 0x400, 0x800);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.min_filesize, 0x800 + 0x400);
    }

    #[test]
    fn test_ds_store_no_match() {
        let sig = DsStoreSignature;
        // Mismatched offset fields.
        assert!(sig
            .header_check(&make_header(0x800, 0x400, 0x900), 0)
            .is_none());
        // Too short.
        assert!(sig.header_check(&[0u8; 8], 0).is_none());
    }
}
