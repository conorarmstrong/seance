use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// XFI Electronic Fuel Injection systems carving signature. Ported from
/// PhotoRec file_xfi.c. Header: the 32-byte ASCII string ", Fuel Air Spark
/// Technologies   " (0x2C prefix, three trailing spaces) at offset 0x10.
/// No footer; size not encoded.
struct XfiSignature;

const XFI_OFFSET: usize = 0x10;

const XFI_MAGIC: &[u8] = &[
    0x2c, b' ', b'F', b'u', b'e', b'l', b' ', b'A', b'i', b'r', b' ', b'S', b'p', b'a', b'r', b'k',
    b' ', b'T', b'e', b'c', b'h', b'n', b'o', b'l', b'o', b'g', b'i', b'e', b's', b' ', b' ', b' ',
];

impl FileSignature for XfiSignature {
    fn name(&self) -> &str {
        "XFI"
    }
    fn extensions(&self) -> &[&str] {
        &["xfi"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = XFI_OFFSET + XFI_MAGIC.len();
        if buf.len() >= end && &buf[XFI_OFFSET..end] == XFI_MAGIC {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "xfi".to_string(),
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
    registry.register(XFI_OFFSET as u16, XFI_MAGIC, Arc::new(XfiSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xfi_header_match() {
        let mut buf = vec![0u8; XFI_OFFSET + XFI_MAGIC.len()];
        buf[XFI_OFFSET..].copy_from_slice(XFI_MAGIC);
        assert!(XfiSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_xfi_no_match() {
        // Magic bytes present but at the wrong offset (0 instead of 0x10).
        assert!(XfiSignature.header_check(XFI_MAGIC, 0).is_none());
        // Buffer too short to reach the offset.
        assert!(XfiSignature.header_check(&[0u8; 8], 0).is_none());
    }
}
