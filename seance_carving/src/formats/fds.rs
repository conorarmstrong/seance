use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// fwNES Disk Image (with header) carving signature. Header: "FDS" 0x1A (4 bytes) at offset 0.
/// Size is encoded: 16 + numsides * 65500, where numsides is the byte at offset 4.
struct FdsSignature;

const MAGIC: [u8; 4] = [b'F', b'D', b'S', 0x1A];

impl FileSignature for FdsSignature {
    fn name(&self) -> &str {
        "fwNES Disk Image"
    }
    fn extensions(&self) -> &[&str] {
        &["fds"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 4 || buf[0..4] != MAGIC {
            return None;
        }
        let calculated_file_size = if buf.len() >= 5 {
            Some(16 + buf[4] as u64 * 65500)
        } else {
            None
        };
        Some(RecoveryInit {
            min_filesize: 16,
            extension: "fds".to_string(),
            calculated_file_size,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &MAGIC, Arc::new(FdsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fds_header_match() {
        let sig = FdsSignature;
        let buf = [b'F', b'D', b'S', 0x1A, 0x02];
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(16 + 2 * 65500));
    }

    #[test]
    fn test_fds_no_match() {
        let sig = FdsSignature;
        assert!(sig.header_check(b"FDS\x00\x01", 0).is_none());
        assert!(sig.header_check(b"NES", 0).is_none());
    }
}
