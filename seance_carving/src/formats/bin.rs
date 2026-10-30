use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DINO "Ticket.bin" carving signature. Header: 13-byte magic at offset 6 (0x07 0x00 0x07 0x09
/// "TaTickets"). The file
/// size is the u32 LE at offset 2 and must be >= 65. PhotoRec names recoveries
/// "Ticket.bin"; this port uses the "bin" extension (see note).
struct BinSignature;

/// 13-byte magic at offset 6.
const BIN_HEADER: [u8; 13] = [
    0x07, 0x00, 0x07, 0x09, b'T', b'a', b'T', b'i', b'c', b'k', b'e', b't', b's',
];

impl FileSignature for BinSignature {
    fn name(&self) -> &str {
        "DINO Ticket"
    }

    fn extensions(&self) -> &[&str] {
        &["bin"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // size is a u32 LE at offset 2 (before the offset-6 magic).
        if buf.len() < 6 {
            return None;
        }
        let size = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
        if size < 65 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 65,
            extension: "bin".to_string(),
            calculated_file_size: Some(size as u64),
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
    registry.register(6, &BIN_HEADER, Arc::new(BinSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bin_header_match() {
        let sig = BinSignature;
        let mut buf = vec![0u8; 24];
        buf[2..6].copy_from_slice(&100u32.to_le_bytes()); // size >= 65
        buf[6..19].copy_from_slice(&BIN_HEADER);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(100));
    }

    #[test]
    fn test_bin_no_match() {
        let sig = BinSignature;
        let mut buf = vec![0u8; 24];
        buf[2..6].copy_from_slice(&10u32.to_le_bytes()); // size < 65
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&[0u8; 4], 0).is_none());
    }
}
