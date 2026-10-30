use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MAC Address Book (AB) carving signature. Header: "LJ" at offset 0, followed by a marker byte
/// (0x1a or 0x0a), a zero
/// byte, and a big-endian record length (>= 8). No footer.
struct AbSignature;

const AB_MAGIC: &[u8] = b"LJ";

impl FileSignature for AbSignature {
    fn name(&self) -> &str {
        "MAC_ADDRESSBOOK"
    }

    fn extensions(&self) -> &[&str] {
        &["ab"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct ab_header { char magic[4]; uint32_t size (big-endian); }
        if buf.len() >= 8
            && buf[0] == b'L'
            && buf[1] == b'J'
            && (buf[2] == 0x1a || buf[2] == 0x0a)
            && buf[3] == 0x00
        {
            let length = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            if length >= 8 {
                return Some(RecoveryInit {
                    min_filesize: 8,
                    extension: "ab".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, AB_MAGIC, Arc::new(AbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ab_header_match() {
        let sig = AbSignature;
        // "LJ", marker 0x1a, 0x00, then big-endian length 8.
        let buf = [b'L', b'J', 0x1a, 0x00, 0x00, 0x00, 0x00, 0x08];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_ab_no_match() {
        let sig = AbSignature;
        // Wrong marker byte at index 2.
        let buf = [b'L', b'J', 0x00, 0x00, 0x00, 0x00, 0x00, 0x08];
        assert!(sig.header_check(&buf, 0).is_none());
        // Length below minimum (7 < 8).
        let short = [b'L', b'J', 0x0a, 0x00, 0x00, 0x00, 0x00, 0x07];
        assert!(sig.header_check(&short, 0).is_none());
    }
}
