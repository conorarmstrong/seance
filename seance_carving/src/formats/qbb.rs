use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Quickbooks backup (QBB/QBMB/QBW) carving signature. Four magic variants:
///   - `45 86 00 00 06 00 02 00` at offset 0 -> qbb
///   - `45 86 00 00 06 00 01 00` at offset 0 -> qbmb
///   - `56 00 00 00` at offset 4 (with "MAUI" at 0x60) -> qbw, size from block count
///   - `5E BA 7A DA` at offset 0x14 (with "Sybase" at 0x87A) -> qbw
///
/// No footer. The qbb/qbmb record-chain size walk is not implemented (see note);
/// those recover via header magic + max size. qbw size is computed from the
/// 1KiB block count at offset 0x34.
struct QbbSignature;

impl FileSignature for QbbSignature {
    fn name(&self) -> &str {
        "QBB"
    }
    fn extensions(&self) -> &[&str] {
        &["qbb", "qbw", "qbmb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // qbb / qbmb family: magic 45 86 00 00 06 00 TYPE 00 at offset 0.
        if buf.len() >= 8
            && buf[0] == 0x45
            && buf[1] == 0x86
            && buf[2] == 0x00
            && buf[3] == 0x00
            && buf[4] == 0x06
            && buf[5] == 0x00
            && buf[7] == 0x00
            && (buf[6] == 0x01 || buf[6] == 0x02)
        {
            let ext = if buf[6] == 0x01 { "qbmb" } else { "qbb" };
            return Some(RecoveryInit {
                min_filesize: 16,
                extension: ext.to_string(),
                calculated_file_size: None,
            });
        }
        // qbw: magic 56 00 00 00 at offset 4, "MAUI" tag at offset 0x60.
        if buf.len() >= 0x64
            && buf[4] == 0x56
            && buf[5] == 0x00
            && buf[6] == 0x00
            && buf[7] == 0x00
            && &buf[0x60..0x64] == b"MAUI"
        {
            let blocks = u32::from_le_bytes([buf[0x34], buf[0x35], buf[0x36], buf[0x37]]) as u64;
            let calc = (blocks + 1) * 1024;
            return Some(RecoveryInit {
                min_filesize: 1024,
                extension: "qbw".to_string(),
                calculated_file_size: Some(calc),
            });
        }
        // qbw2: magic 5E BA 7A DA at offset 0x14, "Sybase" tag at offset 0x87A.
        if buf.len() >= 0x87A + 6
            && buf[0x14] == 0x5e
            && buf[0x15] == 0xba
            && buf[0x16] == 0x7a
            && buf[0x17] == 0xda
            && &buf[0x87A..0x87A + 6] == b"Sybase"
        {
            return Some(RecoveryInit {
                min_filesize: 16,
                extension: "qbw".to_string(),
                calculated_file_size: None,
            });
        }
        None
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
    registry.register(
        0,
        &[0x45, 0x86, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00],
        Arc::new(QbbSignature),
    );
    registry.register(
        0,
        &[0x45, 0x86, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00],
        Arc::new(QbbSignature),
    );
    registry.register(4, &[0x56, 0x00, 0x00, 0x00], Arc::new(QbbSignature));
    registry.register(0x14, &[0x5e, 0xba, 0x7a, 0xda], Arc::new(QbbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qbb_header_match() {
        let sig = QbbSignature;
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&[0x45, 0x86, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00]);
        let init = sig.header_check(&buf, 0).expect("should match qbb");
        assert_eq!(init.extension, "qbb");

        // qbmb variant (type byte 0x01)
        buf[6] = 0x01;
        let init2 = sig.header_check(&buf, 0).expect("should match qbmb");
        assert_eq!(init2.extension, "qbmb");
    }

    #[test]
    fn test_qbb_no_match() {
        let sig = QbbSignature;
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
        // Right prefix but invalid type byte
        let mut buf = [0u8; 16];
        buf[0..6].copy_from_slice(&[0x45, 0x86, 0x00, 0x00, 0x06, 0x00]);
        buf[6] = 0x09;
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
