use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Mozilla bookmarks (jsonlz4) carving signature. Header: "mozLz40\0" (8 bytes) at offset 0,
/// followed by a
/// little-endian u32 at offset 8 which must be non-zero. Note: that u32 is the
/// UNCOMPRESSED LZ4 size, not the on-disk file size, so it is not used as
/// calculated_file_size; recovery instead scans to the next header / max size.
struct Jsonlz4Signature;

const JSONLZ4_MAGIC: &[u8] = b"mozLz40\x00";

impl FileSignature for Jsonlz4Signature {
    fn name(&self) -> &str {
        "JSONLZ4"
    }
    fn extensions(&self) -> &[&str] {
        &["jsonlz4"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 || &buf[0..8] != JSONLZ4_MAGIC {
            return None;
        }
        let size = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if size == 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 12,
            extension: "jsonlz4".to_string(),
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
    registry.register(0, JSONLZ4_MAGIC, Arc::new(Jsonlz4Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jsonlz4_header_match() {
        let sig = Jsonlz4Signature;
        let mut buf = Vec::new();
        buf.extend_from_slice(JSONLZ4_MAGIC);
        buf.extend_from_slice(&16u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_jsonlz4_no_match() {
        let sig = Jsonlz4Signature;
        // Zero uncompressed size is rejected.
        let mut buf = Vec::new();
        buf.extend_from_slice(JSONLZ4_MAGIC);
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(b"notmozLz40xx", 0).is_none());
    }
}
