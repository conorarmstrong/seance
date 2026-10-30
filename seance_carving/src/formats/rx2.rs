use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// iZotope RX 2 audio repair file carving signature. Header at offset 0: "CAT " with "REX2HEAD" at
/// offset 8. Big-endian size (bytes 4..8) >= 4.
/// Exact size encoded in header: calculated_file_size = size + 8. Enforced by size (no footer).
struct Rx2Signature;

const RX2_MAGIC: &[u8] = b"CAT ";

impl FileSignature for Rx2Signature {
    fn name(&self) -> &str {
        "RX2"
    }
    fn extensions(&self) -> &[&str] {
        &["rx2"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct rx2_header: magic(4) size(4, BE); "REX2HEAD" at offset 8.
        if buf.len() < 16 || &buf[0..RX2_MAGIC.len()] != RX2_MAGIC {
            return None;
        }
        if &buf[8..16] != b"REX2HEAD" {
            return None;
        }
        let size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if size < 4 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 12,
            extension: "rx2".to_string(),
            calculated_file_size: Some(size as u64 + 8),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, RX2_MAGIC, Arc::new(Rx2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rx2_header_match() {
        let sig = Rx2Signature;
        // "CAT " + size=0x10 (BE) + "REX2HEAD"
        let mut buf = RX2_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]);
        buf.extend_from_slice(b"REX2HEAD");
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x10 + 8));
    }

    #[test]
    fn test_rx2_no_match() {
        let sig = Rx2Signature;
        // Missing REX2HEAD tag
        let mut buf = RX2_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]);
        buf.extend_from_slice(b"NOTAHEAD");
        assert!(sig.header_check(&buf, 0).is_none());
        // size < 4
        let mut buf2 = RX2_MAGIC.to_vec();
        buf2.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        buf2.extend_from_slice(b"REX2HEAD");
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
