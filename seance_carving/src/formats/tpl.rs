use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adobe Tool Preset (TPL) carving signature. Header: "8BTP" followed by 0x00 0x00 0x00 at offset 0
/// (7-byte magic).
/// No footer.
struct TplSignature;

const TPL_MAGIC: &[u8] = &[b'8', b'B', b'T', b'P', 0x00, 0x00, 0x00];

impl FileSignature for TplSignature {
    fn name(&self) -> &str {
        "Adobe Tool Preset"
    }
    fn extensions(&self) -> &[&str] {
        &["tpl"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= TPL_MAGIC.len() && &buf[0..TPL_MAGIC.len()] == TPL_MAGIC {
            Some(RecoveryInit {
                min_filesize: TPL_MAGIC.len() as u64,
                extension: "tpl".to_string(),
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
    registry.register(0, TPL_MAGIC, Arc::new(TplSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpl_header_match() {
        let mut buf = TPL_MAGIC.to_vec();
        buf.extend_from_slice(&[0xaa; 8]);
        assert!(TplSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_tpl_no_match() {
        assert!(TplSignature
            .header_check(&[b'8', b'B', b'T', b'Q', 0x00, 0x00, 0x00], 0)
            .is_none());
        assert!(TplSignature.header_check(b"8BT", 0).is_none());
    }
}
