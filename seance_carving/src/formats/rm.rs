use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Real Audio (.RMF) carving signature. Header at offset 0: ".RMF" 00 00 00 12 00. Requires
/// big-endian header_nbr (offset 14) >= 3.
/// No footer/size.
struct RmSignature;

const RM_MAGIC: &[u8] = &[b'.', b'R', b'M', b'F', 0x00, 0x00, 0x00, 0x12, 0x00];

impl FileSignature for RmSignature {
    fn name(&self) -> &str {
        "RM"
    }
    fn extensions(&self) -> &[&str] {
        &["rm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct rm_header: type(4) size(4) version(2) file_version(4) header_nbr(4).
        // header_nbr is big-endian at byte offset 14.
        if buf.len() < 18 || &buf[0..RM_MAGIC.len()] != RM_MAGIC {
            return None;
        }
        let header_nbr = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);
        if header_nbr < 3 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 18,
            extension: "rm".to_string(),
            calculated_file_size: None,
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
    registry.register(0, RM_MAGIC, Arc::new(RmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rm_header_match() {
        let sig = RmSignature;
        // magic (9 bytes) + pad to offset 14 + header_nbr = 3 (big-endian)
        let mut buf = RM_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 5]); // bytes 9..14
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // header_nbr = 3
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_rm_no_match() {
        let sig = RmSignature;
        // Wrong magic
        assert!(sig
            .header_check(
                b"XXXX\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00",
                0
            )
            .is_none());
        // Correct magic but header_nbr < 3
        let mut buf = RM_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 5]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
