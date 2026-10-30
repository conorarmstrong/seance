use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// bzip2 compressed data carving signature. Registered magic: "BZh" (3 bytes) at offset 0.
/// header_check validates the
/// full 10-byte stream header: "BZh", a level digit [0-9], then "1AY&SY" (the
/// compressed block magic). No footer or embedded size.
struct Bz2Signature;

impl FileSignature for Bz2Signature {
    fn name(&self) -> &str {
        "BZ2"
    }

    fn extensions(&self) -> &[&str] {
        &["bz2"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 10
            && buf[0] == b'B'
            && buf[1] == b'Z'
            && buf[2] == b'h'
            && buf[3].is_ascii_digit()
            && buf[4] == b'1'
            && buf[5] == b'A'
            && buf[6] == b'Y'
            && buf[7] == b'&'
            && buf[8] == b'S'
            && buf[9] == b'Y'
        {
            Some(RecoveryInit {
                min_filesize: 10,
                extension: "bz2".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"BZh", Arc::new(Bz2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bz2_header_match() {
        let sig = Bz2Signature;
        assert!(sig.header_check(b"BZh91AY&SY\x00\x00", 0).is_some());
        assert!(sig.header_check(b"BZh11AY&SY----", 0).is_some());
    }

    #[test]
    fn test_bz2_no_match() {
        let sig = Bz2Signature;
        // Right prefix, wrong block magic.
        assert!(sig.header_check(b"BZh9XXXXXX", 0).is_none());
        // Non-digit level.
        assert!(sig.header_check(b"BZhX1AY&SY", 0).is_none());
        assert!(sig.header_check(b"NOTBZIP2!!", 0).is_none());
    }
}
