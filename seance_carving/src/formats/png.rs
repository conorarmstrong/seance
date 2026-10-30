use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PNG file signature detector.
/// Header: 89 50 4E 47 0D 0A 1A 0A
/// Footer: IEND chunk followed by CRC
/// Ref: reference/testdisk/src/file_png.c
struct PngSignature;

impl FileSignature for PngSignature {
    fn name(&self) -> &str {
        "PNG"
    }

    fn extensions(&self) -> &[&str] {
        &["png"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && buf[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            Some(RecoveryInit {
                min_filesize: 67, // Minimum PNG: header + IHDR + IEND
                extension: "png".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Scan for the IEND chunk type (49 45 4E 44), which is followed by a
        // 4-byte CRC: the file ends 4 bytes past the end of the type. The type
        // may straddle two blocks and the CRC may spill into the next one.
        match footer_end_spanning(buf, recovery, b"IEND", 0) {
            Some(end) => DataCheckResult::Stop(end + 4),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {
        // Could verify IEND is present in final bytes
    }

    fn max_file_size(&self) -> u64 {
        64 * 1024 * 1024 // 64 MB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        Arc::new(PngSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_png_header_match() {
        let sig = PngSignature;
        let buf = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_png_header_no_match() {
        let sig = PngSignature;
        let buf = [0xFF, 0xD8, 0xFF, 0xE0]; // JPEG
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_png_iend_detection() {
        let sig = PngSignature;
        let mut recovery = FileRecovery {
            extension: "png".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 67,
            extra: 0,
            extra_bytes: Vec::new(),
        };

        // Buffer containing IEND at position 2
        let mut buf = vec![0u8; 16];
        buf[2..6].copy_from_slice(b"IEND");
        let result = sig.data_check(&buf, &mut recovery);
        // end_pos = 100 + 2 + 4 + 4 = 110
        assert_eq!(result, DataCheckResult::Stop(110));
    }
}
