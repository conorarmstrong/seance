use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WEBP file signature detector.
/// Header: RIFF....WEBP  (52 49 46 46 XX XX XX XX 57 45 42 50)
/// File size from RIFF chunk header at bytes 4-7 (LE u32) + 8
struct WebpSignature;

impl FileSignature for WebpSignature {
    fn name(&self) -> &str {
        "WEBP"
    }

    fn extensions(&self) -> &[&str] {
        &["webp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] == b"WEBP" {
            let chunk_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
            let file_size = chunk_size + 8; // RIFF header is 8 bytes (tag + size)
            if file_size >= 12 && file_size <= self.max_file_size() {
                Some(RecoveryInit {
                    min_filesize: 12,
                    extension: "webp".to_string(),
                    calculated_file_size: Some(file_size),
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // Size-based; this shouldn't be called since we use calculated_file_size
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024 // 100 MB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"RIFF", Arc::new(WebpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webp_header_match() {
        let sig = WebpSignature;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(b"RIFF");
        // Chunk size = 1000
        buf[4..8].copy_from_slice(&1000u32.to_le_bytes());
        buf[8..12].copy_from_slice(b"WEBP");
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.calculated_file_size, Some(1008)); // 1000 + 8
        assert_eq!(init.extension, "webp");
        assert_eq!(init.min_filesize, 12);
    }

    #[test]
    fn test_riff_not_webp() {
        let sig = WebpSignature;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(b"RIFF");
        buf[4..8].copy_from_slice(&1000u32.to_le_bytes());
        buf[8..12].copy_from_slice(b"AVI "); // AVI, not WEBP
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_webp_no_match() {
        let sig = WebpSignature;
        let buf = [0x00u8; 16];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_webp_short_buffer() {
        let sig = WebpSignature;
        // Buffer too short to contain a full RIFF+WEBP header (needs 12 bytes)
        let buf = [0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00]; // 7 bytes
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
