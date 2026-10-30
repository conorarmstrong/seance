use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Clip Studio Paint carving signature. Header: "CSFCHUNK" at offset 0, followed by a big-endian
/// u64 total size
/// which must be in (0x18, 0x100000000]. No footer.
/// PhotoRec's data_check walks "CHNK" records; that stateful walk is degraded
/// here to header validation + min_filesize from the declared size.
struct ClipSignature;

impl FileSignature for ClipSignature {
    fn name(&self) -> &str {
        "Clip Studio Paint"
    }
    fn extensions(&self) -> &[&str] {
        &["clip"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 16 && &buf[0..8] == b"CSFCHUNK" {
            let size = u64::from_be_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            if size > 0x18 && size <= 0x1_0000_0000 {
                return Some(RecoveryInit {
                    min_filesize: size,
                    extension: "clip".to_string(),
                    calculated_file_size: None,
                });
            }
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        // Header declares a size up to 0x100000000 (4 GiB); allow the full range.
        4u64 * 1024 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"CSFCHUNK", Arc::new(ClipSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clip_header_match() {
        let sig = ClipSignature;
        let mut buf = b"CSFCHUNK".to_vec();
        buf.extend_from_slice(&0x1000u64.to_be_bytes()); // size > 0x18
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_clip_no_match() {
        let sig = ClipSignature;
        // Size too small (<= 0x18).
        let mut small = b"CSFCHUNK".to_vec();
        small.extend_from_slice(&0x10u64.to_be_bytes());
        assert!(sig.header_check(&small, 0).is_none());
        // Wrong magic.
        let mut bad = b"XSFCHUNK".to_vec();
        bad.extend_from_slice(&0x1000u64.to_be_bytes());
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
