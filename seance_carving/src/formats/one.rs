use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ONE (Microsoft OneNote) carving signature. Header: 16-byte GUID magic at offset 0. The 32-bit
/// little-endian value at
/// offset 196 is the file size, which must be at least 200. Size-driven
/// recovery; no footer.
struct OneSignature;

const ONE_MAGIC: [u8; 16] = [
    0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3,
];

impl FileSignature for OneSignature {
    fn name(&self) -> &str {
        "ONE"
    }
    fn extensions(&self) -> &[&str] {
        &["one"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 200 && buf[0..16] == ONE_MAGIC {
            let size = (buf[196] as u64)
                + ((buf[197] as u64) << 8)
                + ((buf[198] as u64) << 16)
                + ((buf[199] as u64) << 24);
            if size < 200 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 200,
                extension: "one".to_string(),
                calculated_file_size: Some(size),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &ONE_MAGIC, Arc::new(OneSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_header_match() {
        let sig = OneSignature;
        let mut buf = vec![0u8; 200];
        buf[0..16].copy_from_slice(&ONE_MAGIC);
        buf[196] = 200; // size = 200
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(200));
    }

    #[test]
    fn test_one_no_match() {
        let sig = OneSignature;
        // Correct magic but size below 200.
        let mut buf = vec![0u8; 200];
        buf[0..16].copy_from_slice(&ONE_MAGIC);
        buf[196] = 100;
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let buf2 = vec![0u8; 200];
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
