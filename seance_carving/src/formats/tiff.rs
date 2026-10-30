use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// TIFF image file signature detector.
/// Little-endian: 49 49 2A 00 ("II" + version 42)
/// Big-endian: 4D 4D 00 2A ("MM" + version 42)
/// IFD offset at bytes 4-7 points to first Image File Directory.
/// Size estimated by scanning IFD chain for the maximum data offset + size.
/// Since TIFF structure requires chasing pointers, we use max-size recovery.
/// Ref: TIFF 6.0 specification, reference/testdisk/src/file_tiff.c
struct TiffLeSignature;

impl FileSignature for TiffLeSignature {
    fn name(&self) -> &str {
        "TIFF"
    }

    fn extensions(&self) -> &[&str] {
        &["tif", "tiff", "cr2", "nef", "dng", "arw"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }
        if buf[0..4] != [0x49, 0x49, 0x2A, 0x00] {
            return None;
        }

        // First IFD offset (LE u32 at offset 4)
        let ifd_offset = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        if !(8..=0xFFFFFF).contains(&ifd_offset) {
            return None; // unreasonable IFD offset
        }

        // TIFF files can contain embedded thumbnails and multiple IFDs;
        // calculating exact size requires chasing the full IFD chain.
        // Use max-size recovery instead.
        Some(RecoveryInit {
            min_filesize: 8,
            extension: "tif".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // This registration shares its magic with TIFF_LE, so it must refuse
        // what TIFF_LE refuses: otherwise a stray magic that TIFF_LE rejects
        // still ends a running carve through this one (CARVE-015).
        if recovery.file_size == 0 && !crate::checks::tiff_ifd_plausible(buf, true) {
            return DataCheckResult::Error;
        }
        DataCheckResult::Continue
    }

    fn header_confirmed_by_source(
        &self,
        source: &dyn crate::engine::CarvingDataSource,
        offset: u64,
    ) -> Option<bool> {
        // The directory usually lies past the header block (CARVE-015).
        crate::checks::tiff_ifd_plausible_at(source, offset, true)
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024 * 1024 // 1 GB — RAW camera files can be large
    }
}

struct TiffBeSignature;

impl FileSignature for TiffBeSignature {
    fn name(&self) -> &str {
        "TIFF"
    }

    fn extensions(&self) -> &[&str] {
        &["tif", "tiff"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }
        if buf[0..4] != [0x4D, 0x4D, 0x00, 0x2A] {
            return None;
        }

        let ifd_offset = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        if !(8..=0xFFFFFF).contains(&ifd_offset) {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 8,
            extension: "tif".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // This registration shares its magic with TIFF_BE, so it must refuse
        // what TIFF_BE refuses: otherwise a stray magic that TIFF_BE rejects
        // still ends a running carve through this one (CARVE-015).
        if recovery.file_size == 0 && !crate::checks::tiff_ifd_plausible(buf, false) {
            return DataCheckResult::Error;
        }
        DataCheckResult::Continue
    }

    fn header_confirmed_by_source(
        &self,
        source: &dyn crate::engine::CarvingDataSource,
        offset: u64,
    ) -> Option<bool> {
        // The directory usually lies past the header block (CARVE-015).
        crate::checks::tiff_ifd_plausible_at(source, offset, false)
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        1024 * 1024 * 1024 // 1 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x49, 0x49, 0x2A, 0x00], Arc::new(TiffLeSignature));
    registry.register(0, &[0x4D, 0x4D, 0x00, 0x2A], Arc::new(TiffBeSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tiff_le_match() {
        let sig = TiffLeSignature;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&[0x49, 0x49, 0x2A, 0x00]);
        // IFD offset = 8
        buf[4..8].copy_from_slice(&8u32.to_le_bytes());
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        assert_eq!(init.unwrap().extension, "tif");
    }

    #[test]
    fn test_tiff_be_match() {
        let sig = TiffBeSignature;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&[0x4D, 0x4D, 0x00, 0x2A]);
        buf[4..8].copy_from_slice(&8u32.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_tiff_le_bad_ifd() {
        let sig = TiffLeSignature;
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&[0x49, 0x49, 0x2A, 0x00]);
        // IFD offset = 0 (invalid)
        buf[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_tiff_le_no_match() {
        let sig = TiffLeSignature;
        let buf = vec![0u8; 16];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_tiff_be_no_match() {
        let sig = TiffBeSignature;
        let buf = vec![0u8; 16];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_tiff_too_short() {
        let sig = TiffLeSignature;
        let buf = &[0x49, 0x49, 0x2A, 0x00];
        assert!(sig.header_check(buf, 0).is_none());
    }

    #[test]
    fn test_tiff_camera_raw_extensions() {
        let sig = TiffLeSignature;
        // Verify the extensions list includes camera RAW formats
        assert!(sig.extensions().contains(&"cr2"));
        assert!(sig.extensions().contains(&"nef"));
        assert!(sig.extensions().contains(&"dng"));
    }
}
