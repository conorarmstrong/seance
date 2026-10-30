use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Rhino / openNURBS 3DM carving signature. Header at offset 0: "3D Geometry File Format " (24
/// bytes) followed by an
/// optional run of spaces then a version digit '0'-'9'. No footer.
struct F3dmSignature;

const F3DM_MAGIC: &[u8] = b"3D Geometry File Format ";

impl FileSignature for F3dmSignature {
    fn name(&self) -> &str {
        "3DM"
    }
    fn extensions(&self) -> &[&str] {
        &["3dm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 24 || &buf[0..24] != F3DM_MAGIC {
            return None;
        }
        // Skip spaces after the magic, then require a version digit.
        let mut i = 24;
        while i < buf.len() && buf[i] == b' ' {
            i += 1;
        }
        if i >= buf.len() || buf[i] < b'0' || buf[i] > b'9' {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0,
            extension: "3dm".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, F3DM_MAGIC, Arc::new(F3dmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f3dm_header_match() {
        let sig = F3dmSignature;
        assert!(sig.header_check(b"3D Geometry File Format 3", 0).is_some());
        // spaces then digit
        assert!(sig.header_check(b"3D Geometry File Format 2", 0).is_some());
    }

    #[test]
    fn test_f3dm_no_match() {
        let sig = F3dmSignature;
        // No version digit after magic
        assert!(sig.header_check(b"3D Geometry File Format X", 0).is_none());
        // Wrong magic
        assert!(sig.header_check(b"3D Geometry File Formata2", 0).is_none());
        // Too short
        assert!(sig.header_check(b"3D Geometry", 0).is_none());
    }
}
