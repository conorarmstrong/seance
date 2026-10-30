use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FastTracker II Extended Module (XM) carving signature.
/// Header: "Extended Module: " (17 bytes) at offset 0.
/// PhotoRec's file_check_xm walks the pattern and instrument headers to compute
/// the exact file size; that stateful size calculation is not implemented here
/// (degraded to a header-magic + min/max-size signature).
struct XmSignature;

const XM_MAGIC: &[u8] = b"Extended Module: ";

impl FileSignature for XmSignature {
    fn name(&self) -> &str {
        "XM"
    }
    fn extensions(&self) -> &[&str] {
        &["xm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= XM_MAGIC.len() && &buf[0..XM_MAGIC.len()] == XM_MAGIC {
            Some(RecoveryInit {
                min_filesize: 336 + 29, // Header + 1 instrument
                extension: "xm".to_string(),
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
        256 * 1024 * 1024 // audio module category default
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, XM_MAGIC, Arc::new(XmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xm_header_match() {
        let sig = XmSignature;
        assert!(sig.header_check(b"Extended Module: TITLE", 0).is_some());
    }

    #[test]
    fn test_xm_no_match() {
        let sig = XmSignature;
        assert!(sig.header_check(b"Extended Modul", 0).is_none());
        assert!(sig.header_check(b"NOT A MODULE HEADER", 0).is_none());
    }
}
