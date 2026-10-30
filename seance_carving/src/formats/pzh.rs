use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Presto (PZH) carving signature. Header: {0x00,0x00,0x01,'8','.','0',0x00,0x02,0x05,0x03} at
/// offset 0x9c4. No footer.
/// (PhotoRec's file_rename step is not implemented; carve uses the header magic + min size.)
struct PzhSignature;

const PZH_OFFSET: usize = 0x9c4;
const PZH_MAGIC: &[u8] = &[0x00, 0x00, 0x01, b'8', b'.', b'0', 0x00, 0x02, 0x05, 0x03];

impl FileSignature for PzhSignature {
    fn name(&self) -> &str {
        "PZH"
    }

    fn extensions(&self) -> &[&str] {
        &["pzh"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = PZH_OFFSET + PZH_MAGIC.len();
        if buf.len() >= end && &buf[PZH_OFFSET..end] == PZH_MAGIC {
            Some(RecoveryInit {
                min_filesize: end as u64,
                extension: "pzh".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    /// The magic lies past the engine's 512-byte block: ask to be shown that far.
    fn header_window(&self) -> usize {
        PZH_OFFSET + PZH_MAGIC.len()
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
    registry.register(PZH_OFFSET as u16, PZH_MAGIC, Arc::new(PzhSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pzh_header_match() {
        let sig = PzhSignature;
        let mut buf = vec![0u8; PZH_OFFSET + PZH_MAGIC.len()];
        buf[PZH_OFFSET..].copy_from_slice(PZH_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_pzh_no_match() {
        let sig = PzhSignature;
        // Correct length but wrong bytes at the offset.
        let buf = vec![0u8; PZH_OFFSET + PZH_MAGIC.len()];
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short to reach the offset.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
    }
}
