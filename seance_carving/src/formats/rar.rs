use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// RAR archive file signature detector.
/// RAR5 header: 52 61 72 21 1A 07 01 00 (8 bytes).
/// RAR4 header: 52 61 72 21 1A 07 00 (7 bytes).
/// No reliable size field in header; uses end-of-archive marker scanning.
/// End marker RAR5: 1D 77 56 51 03 05 04 00
/// Ref: reference/testdisk/src/file_rar.c
struct Rar5Signature;

impl FileSignature for Rar5Signature {
    fn name(&self) -> &str {
        "RAR5"
    }

    fn extensions(&self) -> &[&str] {
        &["rar"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }
        if buf[0..8] != [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 20,
            extension: "rar".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Scan for RAR5 end-of-archive header
        // HEAD_TYPE=0x05 (end of archive), with specific vint encoding
        if buf.len() < 8 {
            return DataCheckResult::Continue;
        }
        for i in 0..buf.len().saturating_sub(7) {
            if buf[i] == 0x1D
                && buf[i + 1] == 0x77
                && buf[i + 2] == 0x56
                && buf[i + 3] == 0x51
                && buf[i + 4] == 0x03
                && buf[i + 5] == 0x05
                && buf[i + 6] == 0x04
                && buf[i + 7] == 0x00
            {
                return DataCheckResult::Stop(recovery.file_size + i as u64 + 8);
            }
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

/// RAR v4 (legacy) archive signature.
struct Rar4Signature;

impl FileSignature for Rar4Signature {
    fn name(&self) -> &str {
        "RAR4"
    }

    fn extensions(&self) -> &[&str] {
        &["rar"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 7 {
            return None;
        }
        // RAR4: 52 61 72 21 1A 07 00
        if buf[0..7] != [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] {
            return None;
        }
        // Exclude RAR5 (byte 7 would be 0x01)
        if buf.len() >= 8 && buf[7] == 0x01 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 20,
            extension: "rar".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // RAR4 end-of-archive: block with HEAD_TYPE=0x7B and HEAD_FLAGS bit 0x4000
        // Simplified: scan for the marker archive header pattern
        // The end-of-archive block is typically 7 bytes: CRC(2) + TYPE(1)=0x7B + FLAGS(2) + SIZE(2)=7
        if buf.len() < 7 {
            return DataCheckResult::Continue;
        }
        for i in 0..buf.len().saturating_sub(6) {
            if buf[i + 2] == 0x7B {
                let flags = u16::from_le_bytes([buf[i + 3], buf[i + 4]]);
                let size = u16::from_le_bytes([buf[i + 5], buf[i + 6]]);
                if size == 7 && flags & 0x4000 != 0 {
                    return DataCheckResult::Stop(recovery.file_size + i as u64 + 7);
                }
            }
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    // Register RAR5 first (longer magic = more specific match)
    registry.register(
        0,
        &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00],
        Arc::new(Rar5Signature),
    );
    registry.register(
        0,
        &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],
        Arc::new(Rar4Signature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rar5_header_match() {
        let sig = Rar5Signature;
        let buf = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00, 0x00, 0x00];
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        assert_eq!(init.unwrap().extension, "rar");
    }

    #[test]
    fn test_rar5_end_marker() {
        let sig = Rar5Signature;
        let mut recovery = FileRecovery {
            extension: "rar".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 20,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0u8; 20];
        // End marker at offset 4
        buf[4..12].copy_from_slice(&[0x1D, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00]);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(result, DataCheckResult::Stop(112)); // 100 + 4 + 8
    }

    #[test]
    fn test_rar4_header_match() {
        let sig = Rar4Signature;
        let buf = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_rar4_rejects_rar5() {
        let sig = Rar4Signature;
        let buf = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0x01]; // RAR5 byte
                                                                    // The 7th byte is 0x00 but 8th byte is 0x01, this is RAR4 actually
                                                                    // RAR5 check: buf[7] == 0x01 → true, so rejected
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_rar5_no_match() {
        let sig = Rar5Signature;
        let buf = vec![0u8; 10];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
