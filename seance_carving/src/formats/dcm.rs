use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DICOM (DCM) medical imaging carving signature. Header: "DICM" 0x02 0x00 0x00 0x00 "UL" at offset
/// 0x80 (the 128-byte preamble
/// precedes the "DICM" magic). No footer.
struct DcmSignature;

const DCM_MAGIC: &[u8] = &[b'D', b'I', b'C', b'M', 0x02, 0x00, 0x00, 0x00, b'U', b'L'];
const DCM_OFFSET: usize = 0x80;

impl FileSignature for DcmSignature {
    fn name(&self) -> &str {
        "DICOM"
    }
    fn extensions(&self) -> &[&str] {
        &["dcm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = DCM_OFFSET + DCM_MAGIC.len();
        if buf.len() >= end && &buf[DCM_OFFSET..end] == DCM_MAGIC {
            Some(RecoveryInit {
                min_filesize: end as u64,
                extension: "dcm".to_string(),
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
    registry.register(0x80, DCM_MAGIC, Arc::new(DcmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dcm_header_match() {
        let mut buf = vec![0u8; DCM_OFFSET + DCM_MAGIC.len()];
        buf[DCM_OFFSET..].copy_from_slice(DCM_MAGIC);
        assert!(DcmSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_dcm_no_match() {
        let buf = vec![0u8; DCM_OFFSET + DCM_MAGIC.len()];
        assert!(DcmSignature.header_check(&buf, 0).is_none());
        // Too short to reach the magic offset.
        assert!(DcmSignature.header_check(b"DICM", 0).is_none());
    }
}
