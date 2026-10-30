use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ACE archive carving signature. Header: signature "**ACE**" at byte offset 7. The leading bytes
/// form the
/// first block header (crc16, size, type); the archive-header block must have
/// type 0 and size >= 3.
///
/// NOTE: PhotoRec's file_check walks every block verifying a CRC32 low-16 over
/// each block body. That stateful CRC validation is not portable to a forward
/// data_check, so it is degraded; recovery is bounded by max_file_size.
struct AceSignature;

const ACE_MAGIC: &[u8] = b"**ACE**";

impl FileSignature for AceSignature {
    fn name(&self) -> &str {
        "ACE"
    }

    fn extensions(&self) -> &[&str] {
        &["ace"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // header_ace: crc16 le16(@0), size le16(@2), type(@4); "**ACE**" @7.
        if buf.len() < 14 || &buf[7..14] != ACE_MAGIC {
            return None;
        }
        let size = u16::from_le_bytes([buf[2], buf[3]]);
        if size < 3 || buf[4] != 0 {
            return None;
        }
        Some(RecoveryInit {
            // 2 CRC16 + 2 head size + 1 head type + 2 flags + 7 signature + 16 marker
            min_filesize: 30,
            extension: "ace".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024 // archive
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    // Signature sits 7 bytes into the file (after the first block header).
    registry.register(7, ACE_MAGIC, Arc::new(AceSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> Vec<u8> {
        // crc16, size(le=3), type(0), flags, then "**ACE**"
        let mut b = vec![0u8, 0, 3, 0, 0, 0, 0];
        b.extend_from_slice(ACE_MAGIC);
        b
    }

    #[test]
    fn test_ace_header_match() {
        let sig = AceSignature;
        assert!(sig.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_ace_no_match() {
        let sig = AceSignature;
        // Missing signature at offset 7.
        assert!(sig.header_check(&[0u8; 14], 0).is_none());
        // Correct signature but wrong block type.
        let mut bad = valid_header();
        bad[4] = 1;
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
