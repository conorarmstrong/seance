use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Affinity Designer (afdesign) carving signature. Header: magic {0x00,0xff,'K','A'} at offset 0,
/// with "nsrP" at offset 8.
/// min_filesize is the little-endian zlib_length field at offset 32. No footer.
struct AfdesignSignature;

const AFDESIGN_MAGIC: &[u8] = &[0x00, 0xff, b'K', b'A'];

impl FileSignature for AfdesignSignature {
    fn name(&self) -> &str {
        "AFDESIGN"
    }

    fn extensions(&self) -> &[&str] {
        &["afdesign"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need at least through the zlib_length field (offset 32..40).
        if buf.len() >= 40
            && &buf[0..AFDESIGN_MAGIC.len()] == AFDESIGN_MAGIC
            && &buf[8..12] == b"nsrP"
        {
            let zlib_length = u64::from_le_bytes([
                buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
            ]);
            Some(RecoveryInit {
                min_filesize: zlib_length,
                extension: "afdesign".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, AFDESIGN_MAGIC, Arc::new(AfdesignSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afdesign_header_match() {
        let sig = AfdesignSignature;
        let mut buf = vec![0u8; 40];
        buf[0..AFDESIGN_MAGIC.len()].copy_from_slice(AFDESIGN_MAGIC);
        buf[8..12].copy_from_slice(b"nsrP");
        buf[32] = 0x64; // zlib_length little-endian = 100
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.min_filesize, 100);
    }

    #[test]
    fn test_afdesign_no_match() {
        let sig = AfdesignSignature;
        // Correct leading magic but missing "nsrP" at offset 8.
        let mut buf = vec![0u8; 40];
        buf[0..AFDESIGN_MAGIC.len()].copy_from_slice(AFDESIGN_MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        assert!(sig.header_check(&[0u8; 40], 0).is_none());
    }
}
