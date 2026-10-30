use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// 7-Zip archive file signature detector.
/// Header: 37 7A BC AF 27 1C (6 bytes at offset 0).
/// Next header offset at offset 0x0C (8 bytes LE) + next header size at 0x14 (8 bytes LE).
/// File size = 0x20 (signature header) + next_header_offset + next_header_size.
/// Ref: reference/testdisk/src/file_7z.c, 7z format specification
struct SevenZSignature;

impl FileSignature for SevenZSignature {
    fn name(&self) -> &str {
        "7Z"
    }

    fn extensions(&self) -> &[&str] {
        &["7z"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x20 {
            return None;
        }
        if buf[0..6] != [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
            return None;
        }

        // NextHeaderOffset at offset 0x0C (8 bytes LE)
        let next_header_offset = u64::from_le_bytes([
            buf[0x0C], buf[0x0D], buf[0x0E], buf[0x0F], buf[0x10], buf[0x11], buf[0x12], buf[0x13],
        ]);

        // NextHeaderSize at offset 0x14 (8 bytes LE)
        let next_header_size = u64::from_le_bytes([
            buf[0x14], buf[0x15], buf[0x16], buf[0x17], buf[0x18], buf[0x19], buf[0x1A], buf[0x1B],
        ]);

        // File size = signature header (0x20) + next_header_offset + next_header_size
        let file_size = 0x20u64
            .saturating_add(next_header_offset)
            .saturating_add(next_header_size);

        if file_size < 0x20 || file_size > self.max_file_size() {
            return Some(RecoveryInit {
                min_filesize: 0x20,
                extension: "7z".to_string(),
                calculated_file_size: None,
            });
        }

        Some(RecoveryInit {
            min_filesize: 0x20,
            extension: "7z".to_string(),
            calculated_file_size: Some(file_size),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        Arc::new(SevenZSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_7z_header(next_header_offset: u64, next_header_size: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x20];
        buf[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
        buf[0x0C..0x14].copy_from_slice(&next_header_offset.to_le_bytes());
        buf[0x14..0x1C].copy_from_slice(&next_header_size.to_le_bytes());
        buf
    }

    #[test]
    fn test_7z_header_match() {
        let sig = SevenZSignature;
        let buf = make_7z_header(1000, 200);
        let init = sig.header_check(&buf, 0).unwrap();
        // 0x20 + 1000 + 200 = 1232
        assert_eq!(init.calculated_file_size, Some(1232));
    }

    #[test]
    fn test_7z_large_archive() {
        let sig = SevenZSignature;
        let buf = make_7z_header(100 * 1024 * 1024, 1024);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(
            init.calculated_file_size,
            Some(0x20 + 100 * 1024 * 1024 + 1024)
        );
    }

    #[test]
    fn test_7z_no_match() {
        let sig = SevenZSignature;
        let buf = vec![0u8; 0x20];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_7z_too_short() {
        let sig = SevenZSignature;
        let buf = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
        assert!(sig.header_check(buf, 0).is_none());
    }
}
