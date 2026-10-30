use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Snagit carving signature. Header at offset 0: 0xcb "TSCSNAG". min_filesize 24+512.
/// PhotoRec validates via file_check_doc_aux (OLE2 compound-document FAT
/// walk starting at offset 24); that structural check is degraded here to a
/// header-magic + minimum-size signature. See `note`.
const SNAG_MAGIC: [u8; 8] = [0xcb, b'T', b'S', b'C', b'S', b'N', b'A', b'G'];

struct SnagSignature;

impl FileSignature for SnagSignature {
    fn name(&self) -> &str {
        "Snagit"
    }
    fn extensions(&self) -> &[&str] {
        &["snag"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SNAG_MAGIC.len() && buf[..SNAG_MAGIC.len()] == SNAG_MAGIC {
            Some(RecoveryInit {
                min_filesize: 24 + 512,
                extension: "snag".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &SNAG_MAGIC, Arc::new(SnagSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snag_header_match() {
        let sig = SnagSignature;
        let mut buf = SNAG_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 16]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_snag_no_match() {
        let sig = SnagSignature;
        assert!(sig.header_check(b"TSCSNAG", 0).is_none());
        assert!(sig.header_check(b"\xcbTSCSNAX", 0).is_none());
    }
}
