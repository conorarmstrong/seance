use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Blender (.blend) carving signature. Header: "BLENDER" at offset 0, followed by a pointer-size
/// byte ('_'=4-byte,
/// '-'=8-byte) at offset 7 and an endianness byte ('v'=little-endian) at offset 8.
///
/// NOTE: PhotoRec walks the block list (4/8-byte pointer, LE/BE variants) using
/// each block's size field until the trailing "ENDB" block, deriving the exact
/// file size. That stateful block walk is not portable to a forward data_check
/// (a raw "ENDB" scan risks truncating on in-data matches), so it is degraded;
/// recovery is bounded by max_file_size.
struct BldSignature;

impl FileSignature for BldSignature {
    fn name(&self) -> &str {
        "BLEND"
    }

    fn extensions(&self) -> &[&str] {
        &["blend"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 || &buf[0..7] != b"BLENDER" {
            return None;
        }
        // Pointer-size byte: '_' (4-byte) or '-' (8-byte).
        if buf[7] != b'_' && buf[7] != b'-' {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 12,
            extension: "blend".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, b"BLENDER", Arc::new(BldSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bld_header_match() {
        let sig = BldSignature;
        // 4-byte pointer, little-endian, version 280
        assert!(sig.header_check(b"BLENDER_v280", 0).is_some());
        // 8-byte pointer, big-endian
        assert!(sig.header_check(b"BLENDER-V280", 0).is_some());
    }

    #[test]
    fn test_bld_no_match() {
        let sig = BldSignature;
        // Wrong magic.
        assert!(sig.header_check(b"NOTBLEND", 0).is_none());
        // Correct magic but invalid pointer-size byte.
        assert!(sig.header_check(b"BLENDERxv280", 0).is_none());
        // Too short.
        assert!(sig.header_check(b"BLENDE", 0).is_none());
    }
}
