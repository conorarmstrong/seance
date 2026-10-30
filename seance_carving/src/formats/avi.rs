use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AVI file signature detector.
/// Header: RIFF....AVI  (52 49 46 46 XX XX XX XX 41 56 49 20)
/// File size from RIFF chunk header at bytes 4-7 (LE u32) + 8
struct AviSignature;

impl FileSignature for AviSignature {
    fn name(&self) -> &str {
        "AVI"
    }

    fn extensions(&self) -> &[&str] {
        &["avi"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] == b"AVI " {
            let chunk_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
            let file_size = chunk_size + 8; // RIFF header is 8 bytes (tag + size)
            if file_size >= 12 && file_size <= self.max_file_size() {
                Some(RecoveryInit {
                    min_filesize: 12,
                    extension: "avi".to_string(),
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
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"RIFF", Arc::new(AviSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avi_header_match() {
        let sig = AviSignature;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(b"RIFF");
        // Chunk size = 1000
        buf[4..8].copy_from_slice(&1000u32.to_le_bytes());
        buf[8..12].copy_from_slice(b"AVI ");
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        assert_eq!(init.unwrap().calculated_file_size, Some(1008)); // 1000 + 8
    }

    #[test]
    fn test_riff_not_avi() {
        let sig = AviSignature;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(b"RIFF");
        buf[4..8].copy_from_slice(&1000u32.to_le_bytes());
        buf[8..12].copy_from_slice(b"WAVE"); // WAV, not AVI
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_avi_no_match() {
        let sig = AviSignature;
        let buf = [0x00u8; 16];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
