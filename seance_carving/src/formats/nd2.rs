use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ND2 (Nikon NIS-Elements) carving signature. Header: ASCII "ND2 FILE SIGNATURE CHUNK NAME01!Ver"
/// at offset 0x10, followed
/// by an ASCII digit at offset 0x33. No footer; header-only detection.
struct Nd2Signature;

const ND2_MAGIC: &[u8] = b"ND2 FILE SIGNATURE CHUNK NAME01!Ver";
const ND2_OFFSET: usize = 0x10;

impl FileSignature for Nd2Signature {
    fn name(&self) -> &str {
        "ND2"
    }
    fn extensions(&self) -> &[&str] {
        &["nd2"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let magic_end = ND2_OFFSET + ND2_MAGIC.len();
        if buf.len() > magic_end
            && &buf[ND2_OFFSET..magic_end] == ND2_MAGIC
            && buf[magic_end].is_ascii_digit()
        {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "nd2".to_string(),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(ND2_OFFSET as u16, ND2_MAGIC, Arc::new(Nd2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nd2_header_match() {
        let sig = Nd2Signature;
        let mut buf = vec![0u8; 0x34];
        buf[ND2_OFFSET..ND2_OFFSET + ND2_MAGIC.len()].copy_from_slice(ND2_MAGIC);
        buf[0x33] = b'5';
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_nd2_no_match() {
        let sig = Nd2Signature;
        // Correct magic but non-digit trailing byte.
        let mut buf = vec![0u8; 0x34];
        buf[ND2_OFFSET..ND2_OFFSET + ND2_MAGIC.len()].copy_from_slice(ND2_MAGIC);
        buf[0x33] = b'X';
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let buf2 = vec![0u8; 0x34];
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
