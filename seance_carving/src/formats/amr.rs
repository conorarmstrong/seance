use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adaptive Multi-Rate audio carving signature. Header: "#!AMR\n" at offset 0, with a validity
/// check on the first frame
/// header byte at offset 6. No footer.
struct AmrSignature;

const AMR_MAGIC: &[u8] = &[b'#', b'!', b'A', b'M', b'R', 0x0a];

impl FileSignature for AmrSignature {
    fn name(&self) -> &str {
        "AMR"
    }

    fn extensions(&self) -> &[&str] {
        &["amr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 10 || &buf[0..6] != AMR_MAGIC {
            return None;
        }
        // First frame-header byte must have reserved bits clear and not be all-zero.
        if buf[6] & 0x83 != 0 {
            return None;
        }
        if buf[6] == 0 && buf[7] == 0 && buf[8] == 0 && buf[9] == 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 10,
            extension: "amr".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, AMR_MAGIC, Arc::new(AmrSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amr_header_match() {
        // buf[6]=0x04 -> (0x04 & 0x83)==0, frame-type bits (0x04>>3)=0, not all zero.
        let buf = [b'#', b'!', b'A', b'M', b'R', 0x0a, 0x04, 0x00, 0x00, 0x00];
        assert!(AmrSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_amr_no_match() {
        // Wrong magic.
        assert!(AmrSignature
            .header_check(b"#!XYZ\n\x04\x00\x00\x00", 0)
            .is_none());
        // Reserved bits set in frame byte.
        let bad = [b'#', b'!', b'A', b'M', b'R', 0x0a, 0x01, 0x00, 0x00, 0x00];
        assert!(AmrSignature.header_check(&bad, 0).is_none());
    }
}
