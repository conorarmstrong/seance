use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// VirtualDJ (VDJ) carving signature. Header: "VDJ" 0x00 0x00 0x00 0x00 0x00 0x24 0x00 0x00 0x00 at
/// offset 0
/// (12-byte magic). No footer.
struct VdjSignature;

const VDJ_MAGIC: &[u8] = &[
    b'V', b'D', b'J', 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
];

impl FileSignature for VdjSignature {
    fn name(&self) -> &str {
        "VirtualDJ"
    }
    fn extensions(&self) -> &[&str] {
        &["vdj"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= VDJ_MAGIC.len() && &buf[0..VDJ_MAGIC.len()] == VDJ_MAGIC {
            Some(RecoveryInit {
                min_filesize: VDJ_MAGIC.len() as u64,
                extension: "vdj".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, VDJ_MAGIC, Arc::new(VdjSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdj_header_match() {
        let mut buf = VDJ_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(VdjSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_vdj_no_match() {
        let mut buf = VDJ_MAGIC.to_vec();
        buf[8] = 0x00;
        assert!(VdjSignature.header_check(&buf, 0).is_none());
        assert!(VdjSignature.header_check(b"VDJ", 0).is_none());
    }
}
