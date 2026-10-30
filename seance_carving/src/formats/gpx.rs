use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// GPX (Guitar Pro 6) carving signature. Header: "BCFZ" at offset 0, plus an 8-byte secondary magic
/// {0x68,0x48,0x68,0xcd,0x4c,0x00,0x01,0x80} at offset 8. No footer.
struct GpxSignature;

const GPX_MAGIC: &[u8] = b"BCFZ";
const GPX_SECONDARY: &[u8] = &[0x68, 0x48, 0x68, 0xcd, 0x4c, 0x00, 0x01, 0x80];

impl FileSignature for GpxSignature {
    fn name(&self) -> &str {
        "GPX"
    }
    fn extensions(&self) -> &[&str] {
        &["gpx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 16 && &buf[0..4] == GPX_MAGIC && &buf[8..16] == GPX_SECONDARY {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "gpx".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, GPX_MAGIC, Arc::new(GpxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpx_header_match() {
        let sig = GpxSignature;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"BCFZ");
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&[0x68, 0x48, 0x68, 0xcd, 0x4c, 0x00, 0x01, 0x80]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_gpx_no_match() {
        let sig = GpxSignature;
        // Correct leading magic but wrong secondary magic.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"BCFZ");
        buf.extend_from_slice(&[0u8; 12]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
    }
}
