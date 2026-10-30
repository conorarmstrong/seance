use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FIT (Flexible & Interoperable Data Transfer / Garmin track) carving
/// signature. Header: ".FIT" signature at offset 8; header_size byte at offset 0 and a
/// little-endian data_size at offset 4 encode the exact file size. No footer.
struct FitSignature;

const FIT_MAGIC: &[u8] = b".FIT";

impl FileSignature for FitSignature {
    fn name(&self) -> &str {
        "FIT"
    }
    fn extensions(&self) -> &[&str] {
        &["fit"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 || &buf[8..12] != FIT_MAGIC {
            return None;
        }
        let header_size = buf[0] as u64;
        if header_size < 12 {
            return None;
        }
        let data_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        let mut calc = data_size + header_size;
        if buf[0] >= 14 {
            calc += 2; // CRC at the end of the file
        }
        Some(RecoveryInit {
            min_filesize: 12,
            extension: "fit".to_string(),
            calculated_file_size: Some(calc),
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
    registry.register(8, FIT_MAGIC, Arc::new(FitSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fit_header_match() {
        let sig = FitSignature;
        // header_size=12, protocol=1, profile_version=0, data_size=100, ".FIT"
        let mut buf = vec![12u8, 1, 0, 0];
        buf.extend_from_slice(&[100, 0, 0, 0]); // data_size le32
        buf.extend_from_slice(FIT_MAGIC);
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(112)); // 100 + 12
    }

    #[test]
    fn test_fit_no_match() {
        let sig = FitSignature;
        // Wrong signature bytes at offset 8.
        let buf = vec![12u8, 1, 0, 0, 0, 0, 0, 0, b'X', b'X', b'X', b'X'];
        assert!(sig.header_check(&buf, 0).is_none());
        // Correct signature but header_size too small.
        let mut buf2 = vec![8u8, 1, 0, 0, 0, 0, 0, 0];
        buf2.extend_from_slice(FIT_MAGIC);
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
