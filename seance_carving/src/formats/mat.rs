use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Matlab MAT-file carving signature. Header: "MATLAB " at offset 0, plus a version marker at 0x7c
/// that is either
/// little-endian {0x00,0x01,'I','M'} or big-endian {0x01,0x00,'M','I'}. No footer.
struct MatSignature;

const MAT_MAGIC: &[u8] = b"MATLAB ";
const MAT_LE: &[u8] = &[0x00, 0x01, b'I', b'M'];
const MAT_BE: &[u8] = &[0x01, 0x00, b'M', b'I'];

impl FileSignature for MatSignature {
    fn name(&self) -> &str {
        "MAT"
    }
    fn extensions(&self) -> &[&str] {
        &["mat"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x80
            && &buf[0..MAT_MAGIC.len()] == MAT_MAGIC
            && (&buf[0x7c..0x80] == MAT_LE || &buf[0x7c..0x80] == MAT_BE)
        {
            Some(RecoveryInit {
                min_filesize: 0x80,
                extension: "mat".to_string(),
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
        10 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MAT_MAGIC, Arc::new(MatSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf(marker: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x80];
        buf[0..MAT_MAGIC.len()].copy_from_slice(MAT_MAGIC);
        buf[0x7c..0x80].copy_from_slice(marker);
        buf
    }

    #[test]
    fn test_mat_header_match() {
        let sig = MatSignature;
        assert!(sig.header_check(&make_buf(MAT_LE), 0).is_some());
        assert!(sig.header_check(&make_buf(MAT_BE), 0).is_some());
    }

    #[test]
    fn test_mat_no_match() {
        let sig = MatSignature;
        // Correct magic but bad version marker.
        assert!(sig
            .header_check(&make_buf(&[0x00, 0x00, 0x00, 0x00]), 0)
            .is_none());
        // Wrong magic.
        let mut buf = make_buf(MAT_LE);
        buf[0] = b'X';
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short.
        assert!(sig.header_check(MAT_MAGIC, 0).is_none());
    }
}
