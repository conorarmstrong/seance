use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// BMP file signature detector.
/// Header: 42 4D (BM) at offset 0
/// File size is stored in bytes 2-5 (LE u32). `BM` and a plausible size are not
/// enough (random data has both about once in a million blocks), so the rest of
/// the file header is checked too: the reserved bytes 6..10 are zero, the pixel
/// data starts after the file header and the DIB header (and inside the file),
/// and the DIB header size is one of the sizes the format defines.
struct BmpSignature;

/// The DIB header sizes in use: BITMAPCOREHEADER (12), OS/2 2.x (64), and the
/// BITMAPINFOHEADER family (40, 52, 56, 108, 124).
const DIB_HEADER_SIZES: [u32; 7] = [12, 40, 52, 56, 64, 108, 124];

impl FileSignature for BmpSignature {
    fn name(&self) -> &str {
        "BMP"
    }

    fn extensions(&self) -> &[&str] {
        &["bmp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 18 && buf[0] == b'B' && buf[1] == b'M' {
            let u32_at =
                |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
            let file_size = u32_at(2) as u64;
            let pixel_offset = u32_at(10);
            let dib_size = u32_at(14);
            let header_ok = u32_at(6) == 0
                && DIB_HEADER_SIZES.contains(&dib_size)
                && pixel_offset as u64 >= 14 + dib_size as u64
                && (pixel_offset as u64) < file_size;
            if header_ok && file_size >= 54 && file_size <= self.max_file_size() {
                Some(RecoveryInit {
                    min_filesize: 54, // BMP header + DIB header minimum
                    extension: "bmp".to_string(),
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
        256 * 1024 * 1024 // 256 MB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x42, 0x4D], Arc::new(BmpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real file header: reserved 0, pixel data at 54, a 40-byte DIB header.
    fn bmp_header(file_size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[0] = b'B';
        buf[1] = b'M';
        buf[2..6].copy_from_slice(&file_size.to_le_bytes());
        buf[10..14].copy_from_slice(&54u32.to_le_bytes());
        buf[14..18].copy_from_slice(&40u32.to_le_bytes());
        buf
    }

    /// `BM` and a plausible size with random bytes behind them is not a BMP.
    #[test]
    fn test_bmp_random_looking_header_is_rejected() {
        let sig = BmpSignature;
        let good = bmp_header(1024);
        assert!(sig.header_check(&good, 0).is_some());
        let mut reserved = good.clone();
        reserved[7] = 1; // reserved bytes must be zero
        assert!(sig.header_check(&reserved, 0).is_none());
        let mut dib = good.clone();
        dib[14..18].copy_from_slice(&41u32.to_le_bytes()); // not a defined DIB size
        assert!(sig.header_check(&dib, 0).is_none());
        let mut early = good.clone();
        early[10..14].copy_from_slice(&20u32.to_le_bytes()); // inside the headers
        assert!(sig.header_check(&early, 0).is_none());
        let mut beyond = good.clone();
        beyond[10..14].copy_from_slice(&2048u32.to_le_bytes()); // past the file
        assert!(sig.header_check(&beyond, 0).is_none());
        // Too short to hold the DIB header size.
        assert!(sig.header_check(&good[..17], 0).is_none());
        // A zeroed body behind BM and a size (the old accepted shape).
        let mut zero = vec![0u8; 64];
        zero[0] = b'B';
        zero[1] = b'M';
        zero[2..6].copy_from_slice(&1024u32.to_le_bytes());
        assert!(sig.header_check(&zero, 0).is_none());
    }

    #[test]
    fn test_bmp_header_match() {
        let sig = BmpSignature;
        let buf = bmp_header(1024);
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        assert_eq!(init.unwrap().calculated_file_size, Some(1024));
    }

    #[test]
    fn test_bmp_too_small() {
        let sig = BmpSignature;
        // File size = 10 (below minimum 54)
        let buf = bmp_header(10);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_bmp_no_match() {
        let sig = BmpSignature;
        let buf = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
