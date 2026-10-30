use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Kaydara FBX 3D file carving signature. Header: "Kaydara FBX Binary " (20 bytes, two trailing
/// spaces) at offset 0.
/// PhotoRec's footer is 11 NUL bytes located via a backward file_search_footer
/// (extra_length 237). An all-zero footer cannot be faithfully translated to the
/// forward-streaming data_check model without truncating on the first zero run,
/// so this is ported as a header-only signature (see note).
struct FbxSignature;

const MAGIC: &[u8] = b"Kaydara FBX Binary  ";

impl FileSignature for FbxSignature {
    fn name(&self) -> &str {
        "FBX"
    }
    fn extensions(&self) -> &[&str] {
        &["fbx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 20 && &buf[0..20] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 20,
                extension: "fbx".to_string(),
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
    registry.register(0, MAGIC, Arc::new(FbxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fbx_header_match() {
        let sig = FbxSignature;
        assert!(sig.header_check(b"Kaydara FBX Binary  \x00", 0).is_some());
    }

    #[test]
    fn test_fbx_no_match() {
        let sig = FbxSignature;
        assert!(sig.header_check(b"Kaydara FBX ASCII   ", 0).is_none());
        assert!(sig.header_check(b"Kaydara", 0).is_none());
    }
}
