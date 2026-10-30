use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Pinnacle Studio (.axp) carving signature. Header: UTF-16LE XML prologue `<?xml version="1.0"
/// encoding="UTF-16"?>\r\n<VFNGDocument>`
/// (112 bytes at offset 0). Footer: UTF-16LE `</VFNGDocument>\r\n` (34 bytes).
struct AxpSignature;

/// 112-byte UTF-16LE header magic.
const AXP_HEADER: [u8; 112] = [
    0xff, 0xfe, 0x3c, 0x00, 0x3f, 0x00, b'x', 0x00, b'm', 0x00, b'l', 0x00, b' ', 0x00, b'v', 0x00,
    b'e', 0x00, b'r', 0x00, b's', 0x00, b'i', 0x00, b'o', 0x00, b'n', 0x00, 0x3d, 0x00, 0x22, 0x00,
    b'1', 0x00, b'.', 0x00, b'0', 0x00, 0x22, 0x00, b' ', 0x00, b'e', 0x00, b'n', 0x00, b'c', 0x00,
    b'o', 0x00, b'd', 0x00, b'i', 0x00, b'n', 0x00, b'g', 0x00, 0x3d, 0x00, 0x22, 0x00, b'U', 0x00,
    b'T', 0x00, b'F', 0x00, 0x2d, 0x00, b'1', 0x00, b'6', 0x00, 0x22, 0x00, 0x3f, 0x00, 0x3e, 0x00,
    0x0d, 0x00, 0x0a, 0x00, 0x3c, 0x00, b'V', 0x00, b'F', 0x00, b'N', 0x00, b'G', 0x00, b'D', 0x00,
    b'o', 0x00, b'c', 0x00, b'u', 0x00, b'm', 0x00, b'e', 0x00, b'n', 0x00, b't', 0x00, 0x3e, 0x00,
];

/// 34-byte UTF-16LE footer `</VFNGDocument>\r\n`.
const AXP_FOOTER: [u8; 34] = [
    b'<', 0, b'/', 0, b'V', 0, b'F', 0, b'N', 0, b'G', 0, b'D', 0, b'o', 0, b'c', 0, b'u', 0, b'm',
    0, b'e', 0, b'n', 0, b't', 0, b'>', 0, 0x0d, 0, 0x0a, 0,
];

impl FileSignature for AxpSignature {
    fn name(&self) -> &str {
        "Pinnacle Studio"
    }

    fn extensions(&self) -> &[&str] {
        &["axp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= AXP_HEADER.len() && buf[..AXP_HEADER.len()] == AXP_HEADER {
            Some(RecoveryInit {
                min_filesize: 0x70 + 34,
                extension: "axp".to_string(),
                calculated_file_size: None, // footer determines end
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        match footer_end_spanning(buf, recovery, &AXP_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &AXP_HEADER, Arc::new(AxpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axp_header_match() {
        let sig = AxpSignature;
        let mut buf = AXP_HEADER.to_vec();
        buf.resize(200, 0);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_axp_no_match() {
        let sig = AxpSignature;
        let mut buf = AXP_HEADER.to_vec();
        buf.resize(200, 0);
        buf[0] = 0x00; // break the BOM
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"not axp", 0).is_none());
    }

    #[test]
    fn test_axp_footer_detection() {
        let sig = AxpSignature;
        let mut recovery = FileRecovery {
            extension: "axp".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 146,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0u8; 8];
        buf.extend_from_slice(&AXP_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(result, DataCheckResult::Stop(100 + 8 + 34));
    }
}
