use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ICC color profile carving signature. Header: profile-size (BE uint32) at offset 0 followed by
/// the "acsp" signature
/// at offset 36. Bytes 10, 11 and 100..128 must be zero and the size must be at
/// least 128. The BE uint32 at offset 0 encodes the exact file size.
struct IccSignature;

const ICC_MAGIC: &[u8] = b"acsp";

impl FileSignature for IccSignature {
    fn name(&self) -> &str {
        "ICC"
    }
    fn extensions(&self) -> &[&str] {
        &["icc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 128 || &buf[36..40] != ICC_MAGIC {
            return None;
        }
        let file_size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        if file_size < 128 || buf[10] != 0 || buf[11] != 0 {
            return None;
        }
        if buf[100..128].iter().any(|&b| b != 0) {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 128,
            extension: "icc".to_string(),
            calculated_file_size: Some(file_size),
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
    // "acsp" signature located 36 bytes into the profile header.
    registry.register(36, ICC_MAGIC, Arc::new(IccSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icc_header_match() {
        let sig = IccSignature;
        let mut buf = [0u8; 128];
        // size = 200 (>= 128) big-endian at offset 0
        buf[0..4].copy_from_slice(&200u32.to_be_bytes());
        buf[36..40].copy_from_slice(b"acsp");
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(200));
    }

    #[test]
    fn test_icc_no_match() {
        let sig = IccSignature;
        // no "acsp" signature
        let buf = [0u8; 128];
        assert!(sig.header_check(&buf, 0).is_none());
        // acsp present but size < 128
        let mut buf2 = [0u8; 128];
        buf2[36..40].copy_from_slice(b"acsp");
        buf2[0..4].copy_from_slice(&50u32.to_be_bytes());
        assert!(sig.header_check(&buf2, 0).is_none());
        // too short
        assert!(sig.header_check(&[0u8; 40], 0).is_none());
    }
}
