use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Veeam Incremental Backup (VIB) carving signature. Header: 0x01 0x00 0x00 0x00 0x03 0x00 0x00
/// 0x00 "md5" 0x00 at
/// offset 4 (12-byte magic). No footer.
struct VibSignature;

const VIB_MAGIC: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, b'm', b'd', b'5', 0x00,
];
const VIB_OFFSET: usize = 4;

impl FileSignature for VibSignature {
    fn name(&self) -> &str {
        "Veeam Incremental Backup"
    }
    fn extensions(&self) -> &[&str] {
        &["vib"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = VIB_OFFSET + VIB_MAGIC.len();
        if buf.len() >= end && &buf[VIB_OFFSET..end] == VIB_MAGIC {
            Some(RecoveryInit {
                min_filesize: end as u64,
                extension: "vib".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(VIB_OFFSET as u16, VIB_MAGIC, Arc::new(VibSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vib_header_match() {
        let mut buf = vec![0u8; VIB_OFFSET];
        buf.extend_from_slice(VIB_MAGIC);
        assert!(VibSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_vib_no_match() {
        let mut buf = vec![0u8; VIB_OFFSET];
        buf.extend_from_slice(&[
            0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, b'm', b'd', b'4', 0x00,
        ]);
        assert!(VibSignature.header_check(&buf, 0).is_none());
        // too short to reach the magic offset
        assert!(VibSignature.header_check(&[0u8; 8], 0).is_none());
    }
}
