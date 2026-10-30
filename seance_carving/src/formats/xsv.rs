use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// XBOX GTA San Andreas save file carving signature. Header: "BLOCKL" 0xDC 0x1D 'd' at offset 20.
/// PhotoRec recovers a
/// fixed-size file of 202772 bytes (data_check_size + file_check_size). No footer.
struct XsvSignature;

const XSV_OFFSET: usize = 20;

const XSV_MAGIC: &[u8] = &[b'B', b'L', b'O', b'C', b'K', b'L', 0xdc, 0x1d, b'd'];

impl FileSignature for XsvSignature {
    fn name(&self) -> &str {
        "XSV"
    }
    fn extensions(&self) -> &[&str] {
        &["xsv"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = XSV_OFFSET + XSV_MAGIC.len();
        if buf.len() >= end && &buf[XSV_OFFSET..end] == XSV_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "xsv".to_string(),
                calculated_file_size: Some(202772),
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
    registry.register(XSV_OFFSET as u16, XSV_MAGIC, Arc::new(XsvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xsv_header_match() {
        let mut buf = vec![0u8; XSV_OFFSET + XSV_MAGIC.len()];
        buf[XSV_OFFSET..].copy_from_slice(XSV_MAGIC);
        let init = XsvSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(202772));
    }

    #[test]
    fn test_xsv_no_match() {
        // Magic present but at the wrong offset (0 instead of 20).
        assert!(XsvSignature.header_check(XSV_MAGIC, 0).is_none());
        // Buffer too short to reach the offset.
        assert!(XsvSignature.header_check(&[0u8; 10], 0).is_none());
    }
}
