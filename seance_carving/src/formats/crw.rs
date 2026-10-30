use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Canon Raw picture carving signature. Header: byte order mark "II" or "MM" at offset 0, then
/// "HEAPCCDR" at offset 6.
/// PhotoRec's file_check scans backwards for footer 0A 30; that trailing-footer
/// search is degraded here to a header-magic + max-size signature.
struct CrwSignature;

impl FileSignature for CrwSignature {
    fn name(&self) -> &str {
        "Canon Raw"
    }
    fn extensions(&self) -> &[&str] {
        &["crw"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 14
            && (&buf[0..2] == b"II" || &buf[0..2] == b"MM")
            && &buf[6..14] == b"HEAPCCDR"
        {
            Some(RecoveryInit {
                min_filesize: 14,
                extension: "crw".to_string(),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"II", Arc::new(CrwSignature));
    registry.register(0, b"MM", Arc::new(CrwSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crw_header_match() {
        let sig = CrwSignature;
        assert!(sig.header_check(b"II\x00\x00\x00\x00HEAPCCDR", 0).is_some());
        assert!(sig.header_check(b"MM\x00\x00\x00\x00HEAPCCDR", 0).is_some());
    }

    #[test]
    fn test_crw_no_match() {
        let sig = CrwSignature;
        // Correct BOM but missing HEAPCCDR marker.
        assert!(sig
            .header_check(b"II\x00\x00\x00\x00NOTACANON", 0)
            .is_none());
        // Wrong BOM.
        assert!(sig.header_check(b"XY\x00\x00\x00\x00HEAPCCDR", 0).is_none());
    }
}
