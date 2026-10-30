use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// lxo/lwo 3D model carving signature. Header: "FORM" at offset 0, then big-endian u32 size at 4,
/// then "LXO" or "LWO" at offset 8.
/// Size is encoded in the header (be32 + 8); no footer.
struct LxoSignature;

impl FileSignature for LxoSignature {
    fn name(&self) -> &str {
        "LXO"
    }
    fn extensions(&self) -> &[&str] {
        &["lxo", "lwo"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct lxo_header: magic[4] + size(be32) + type[3] = 11 bytes.
        if buf.len() < 11 || &buf[0..4] != b"FORM" {
            return None;
        }
        let size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64 + 8;
        if size < 11 {
            return None;
        }
        let extension = if &buf[8..11] == b"LXO" {
            "lxo"
        } else if &buf[8..11] == b"LWO" {
            "lwo"
        } else {
            return None;
        };
        Some(RecoveryInit {
            min_filesize: 11,
            extension: extension.to_string(),
            calculated_file_size: Some(size),
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
    registry.register(0, b"FORM", Arc::new(LxoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lxo_header_match() {
        let sig = LxoSignature;
        // "FORM" + size(be32=100) + "LXO"
        let buf = [b'F', b'O', b'R', b'M', 0, 0, 0, 100, b'L', b'X', b'O'];
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "lxo");
        assert_eq!(init.calculated_file_size, Some(108));
    }

    #[test]
    fn test_lxo_lwo_variant() {
        let sig = LxoSignature;
        let buf = [b'F', b'O', b'R', b'M', 0, 0, 0, 50, b'L', b'W', b'O'];
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "lwo");
    }

    #[test]
    fn test_lxo_no_match() {
        let sig = LxoSignature;
        let buf = [b'F', b'O', b'R', b'M', 0, 0, 0, 100, b'A', b'B', b'C'];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"NOPE", 0).is_none());
    }
}
