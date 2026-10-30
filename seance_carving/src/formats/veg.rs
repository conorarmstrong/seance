use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Sony Vegas (VEG) project carving signature. Header: "riff." at offset 0. The file size is a
/// little-endian
/// u32 stored at offset 0x10 and must be at least 0x14. No footer (size-driven).
struct VegSignature;

const VEG_MAGIC: &[u8] = b"riff.";

impl FileSignature for VegSignature {
    fn name(&self) -> &str {
        "Sony Vegas"
    }
    fn extensions(&self) -> &[&str] {
        &["veg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x14 && &buf[0..5] == VEG_MAGIC {
            let size = u32::from_le_bytes([buf[0x10], buf[0x11], buf[0x12], buf[0x13]]) as u64;
            if size < 0x14 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 0x14,
                extension: "veg".to_string(),
                calculated_file_size: Some(size),
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
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, VEG_MAGIC, Arc::new(VegSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_veg_header_match() {
        let mut buf = vec![0u8; 0x14];
        buf[0..5].copy_from_slice(VEG_MAGIC);
        // size = 0x100 at offset 0x10
        buf[0x10] = 0x00;
        buf[0x11] = 0x01;
        let init = VegSignature.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(0x100));
    }

    #[test]
    fn test_veg_no_match() {
        // size below 0x14 -> reject
        let mut buf = vec![0u8; 0x14];
        buf[0..5].copy_from_slice(VEG_MAGIC);
        assert!(VegSignature.header_check(&buf, 0).is_none());
        // wrong magic
        let mut buf2 = vec![0u8; 0x14];
        buf2[0..5].copy_from_slice(b"RIFFx");
        assert!(VegSignature.header_check(&buf2, 0).is_none());
    }
}
