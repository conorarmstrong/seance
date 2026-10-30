use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ESRI Shapefile carving signature. Header: 0x00 0x00 0x27 0x0a (big-endian file code 9994) at
/// offset 0. Version
/// (le32 @28) must be 1000. File length lives at @24 as a big-endian count of
/// 16-bit words, so byte size = 2 * be32(@24); no footer.
struct ShpSignature;

impl FileSignature for ShpSignature {
    fn name(&self) -> &str {
        "Shapefile"
    }
    fn extensions(&self) -> &[&str] {
        &["shp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need version (le32 @28..32) and size (be32 @24..28).
        if buf.len() < 32 {
            return None;
        }
        let version = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        if version != 1000 {
            return None;
        }
        let words = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]) as u64;
        let size = 2 * words;
        if size < 100 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 100,
            extension: "shp".to_string(),
            calculated_file_size: Some(size),
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
    registry.register(0, &[0x00, 0x00, 0x27, 0x0a], Arc::new(ShpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_header(words: u32, version: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 36];
        buf[0..4].copy_from_slice(&[0x00, 0x00, 0x27, 0x0a]);
        buf[24..28].copy_from_slice(&words.to_be_bytes());
        buf[28..32].copy_from_slice(&version.to_le_bytes());
        buf
    }

    #[test]
    fn test_shp_header_match() {
        let sig = ShpSignature;
        // 100 words -> 200 bytes, version 1000
        let init = sig.header_check(&base_header(100, 1000), 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(200));
    }

    #[test]
    fn test_shp_no_match() {
        let sig = ShpSignature;
        // wrong version
        assert!(sig.header_check(&base_header(100, 999), 0).is_none());
        // size < 100 (10 words -> 20 bytes)
        assert!(sig.header_check(&base_header(10, 1000), 0).is_none());
        // too short
        assert!(sig.header_check(&[0x00, 0x00, 0x27, 0x0a], 0).is_none());
    }
}
