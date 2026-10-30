use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// SunPCI Disk Image (DIM) carving signature. Header: ASCII "SPCI" at offset 0x0c. No footer.
struct DimSignature;

const DIM_OFFSET: usize = 0x0c;

impl FileSignature for DimSignature {
    fn name(&self) -> &str {
        "DIM"
    }
    fn extensions(&self) -> &[&str] {
        &["diskimage"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = DIM_OFFSET + 4;
        if buf.len() >= end && &buf[DIM_OFFSET..end] == b"SPCI" {
            Some(RecoveryInit {
                min_filesize: end as u64,
                extension: "diskimage".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn weak_header(&self) -> bool {
        // No public layout past the magic and no real sample is held, so the
        // magic alone must never split a running carve (CARVE-015).
        true
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0x0c, b"SPCI", Arc::new(DimSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dim_header_match() {
        let mut buf = vec![0u8; DIM_OFFSET + 4];
        buf[DIM_OFFSET..].copy_from_slice(b"SPCI");
        assert!(DimSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_dim_no_match() {
        let buf = vec![0u8; DIM_OFFSET + 4];
        assert!(DimSignature.header_check(&buf, 0).is_none());
        assert!(DimSignature.header_check(b"SPCI", 0).is_none());
    }
}
