use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// xz archive carving signature. Header: 7-byte magic {0xfd,'7','z','X','Z',0x00,0x00} at offset 0.
///
/// NOTE: PhotoRec locates the end via file_search_footer for the 2-byte
/// footer "YZ" scanned backward from EOF. A forward data_check would truncate
/// at the first common "YZ" byte pair, creating false carves, so the footer is
/// not implemented; recovery is bounded by max_file_size instead.
struct XzSignature;

const XZ_MAGIC: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0x00, 0x00];

impl FileSignature for XzSignature {
    fn name(&self) -> &str {
        "XZ"
    }

    fn extensions(&self) -> &[&str] {
        &["xz"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= XZ_MAGIC.len() && &buf[0..XZ_MAGIC.len()] == XZ_MAGIC {
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "xz".to_string(),
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
        512 * 1024 * 1024 // archive
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, XZ_MAGIC, Arc::new(XzSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xz_header_match() {
        let sig = XzSignature;
        let buf = [0xfd, b'7', b'z', b'X', b'Z', 0x00, 0x00, 0x04, 0xe6];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_xz_no_match() {
        let sig = XzSignature;
        // Stream flags byte wrong is fine (not part of magic); test wrong magic.
        assert!(sig
            .header_check(&[0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x00], 0)
            .is_none());
        // Too short.
        assert!(sig.header_check(&[0xfd, b'7', b'z'], 0).is_none());
    }
}
