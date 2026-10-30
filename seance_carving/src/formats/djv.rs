use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DjVu (DJV) carving signature. Header: "AT&TFORM" at offset 0 (magic "AT&T" + chunk type "FORM").
/// The chunk
/// size is a big-endian u32 at offset 8; the recovered file size is size + 12.
/// No footer.
struct DjvSignature;

const DJV_MAX: u64 = 200 * 1024 * 1024;

impl FileSignature for DjvSignature {
    fn name(&self) -> &str {
        "DJV"
    }
    fn extensions(&self) -> &[&str] {
        &["djv"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..8] == b"AT&TFORM" {
            let size = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
            if size == 0 || size + 12 > DJV_MAX {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 12,
                extension: "djv".to_string(),
                calculated_file_size: Some(size + 12),
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
        DJV_MAX
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"AT&TFORM", Arc::new(DjvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djv_header_match() {
        let mut buf = b"AT&TFORM".to_vec();
        buf.extend_from_slice(&1000u32.to_be_bytes());
        let init = DjvSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(1012));
    }

    #[test]
    fn test_djv_no_match() {
        // Wrong magic.
        let mut wrong = b"AT&TXXXX".to_vec();
        wrong.extend_from_slice(&1000u32.to_be_bytes());
        assert!(DjvSignature.header_check(&wrong, 0).is_none());
        // Zero size.
        let mut zero = b"AT&TFORM".to_vec();
        zero.extend_from_slice(&0u32.to_be_bytes());
        assert!(DjvSignature.header_check(&zero, 0).is_none());
    }
}
