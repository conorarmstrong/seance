use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Apple binary property list carving signature. Header: "bplist00" at offset 0. No footer, no
/// size.
/// Note: PhotoRec suppresses this match when already recovering a qbb/sqlite file
/// (header_ignored_adv). That cross-format de-duplication is not modelled here;
/// we emit the plain header-magic signature.
struct PlistSignature;

impl FileSignature for PlistSignature {
    fn name(&self) -> &str {
        "Apple binary property list"
    }
    fn extensions(&self) -> &[&str] {
        &["plist"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..8] == b"bplist00" {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "plist".to_string(),
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
    registry.register(0, b"bplist00", Arc::new(PlistSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plist_header_match() {
        let sig = PlistSignature;
        assert!(sig.header_check(b"bplist00\x00\x00", 0).is_some());
    }

    #[test]
    fn test_plist_no_match() {
        let sig = PlistSignature;
        assert!(sig.header_check(b"bplist01", 0).is_none());
        assert!(sig.header_check(b"bplist", 0).is_none());
    }
}
