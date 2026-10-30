use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// OpenCanvas Image (OCI) carving signature. Header: "OPIM0\0\0\0" (8 bytes) at offset 0. The
/// 4-byte little-endian size
/// follows the 4-char atom type. Atoms are validated ("O" + 3 uppercase letters).
struct OciSignature;

const OCI_MAGIC: &[u8] = b"OPIM0\x00\x00\x00";

impl FileSignature for OciSignature {
    fn name(&self) -> &str {
        "OCI"
    }

    fn extensions(&self) -> &[&str] {
        &["oci"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 || &buf[0..8] != OCI_MAGIC {
            return None;
        }
        let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if size >= 0xFFFF_FFF0 {
            return None;
        }
        // If the buffer reaches the next atom, validate its type ("O" + 3 A-Z).
        let next = 8usize + size as usize;
        if next + 8 <= buf.len() {
            let t = &buf[next..next + 4];
            let ok = t[0] == b'O'
                && t[1].is_ascii_uppercase()
                && t[2].is_ascii_uppercase()
                && t[3].is_ascii_uppercase();
            if !ok {
                return None;
            }
        }
        Some(RecoveryInit {
            min_filesize: 16,
            extension: "oci".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, OCI_MAGIC, Arc::new(OciSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oci_header_match() {
        let sig = OciSignature;
        // 8-byte magic only: next-atom validation skipped, accepts.
        assert!(sig.header_check(OCI_MAGIC, 0).is_some());
    }

    #[test]
    fn test_oci_no_match() {
        let sig = OciSignature;
        assert!(sig.header_check(b"XPIM0\x00\x00\x00", 0).is_none());
        assert!(sig.header_check(b"OPI", 0).is_none());
    }
}
