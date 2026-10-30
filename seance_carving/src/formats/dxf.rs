use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DXF (Drawing Interchange File) carving signature. Header (offset 0): " 0\nSECTION", "
/// 0\r\nSECTION", "999\ndxflib" or "999\r\ndxflib".
/// Footer: "\nEOF" (data_check/file_check search for the trailing EOF marker).
struct DxfSignature;

const DXF_HEADERS: [&[u8]; 4] = [
    b"  0\nSECTION",
    b"  0\r\nSECTION",
    b"999\ndxflib",
    b"999\r\ndxflib",
];

const DXF_FOOTER: &[u8] = b"\nEOF";

impl FileSignature for DxfSignature {
    fn name(&self) -> &str {
        "DXF"
    }

    fn extensions(&self) -> &[&str] {
        &["dxf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        for pat in DXF_HEADERS {
            if buf.len() >= pat.len() && &buf[..pat.len()] == pat {
                return Some(RecoveryInit {
                    min_filesize: 11,
                    extension: "dxf".to_string(),
                    calculated_file_size: None,
                });
            }
        }
        None
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Scan for the "\nEOF" trailer that ends a valid DXF file.
        match footer_end_spanning(buf, recovery, DXF_FOOTER, 0) {
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
    registry.register(0, b"  0\nSECTION", Arc::new(DxfSignature));
    registry.register(0, b"  0\r\nSECTION", Arc::new(DxfSignature));
    registry.register(0, b"999\ndxflib", Arc::new(DxfSignature));
    registry.register(0, b"999\r\ndxflib", Arc::new(DxfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dxf_header_match() {
        let sig = DxfSignature;
        assert!(sig.header_check(b"  0\nSECTION\x00", 0).is_some());
        assert!(sig.header_check(b"  0\r\nSECTION\x00", 0).is_some());
        assert!(sig.header_check(b"999\ndxflib\x00", 0).is_some());
        assert!(sig.header_check(b"999\r\ndxflib\x00", 0).is_some());
    }

    #[test]
    fn test_dxf_no_match() {
        let sig = DxfSignature;
        assert!(sig.header_check(b"  0\nWRONGXX", 0).is_none());
        assert!(sig.header_check(b"NOTDXF", 0).is_none());
    }

    #[test]
    fn test_dxf_footer_detection() {
        let sig = DxfSignature;
        let mut recovery = FileRecovery {
            extension: "dxf".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 11,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let buf = *b"XX\nEOFX";
        assert_eq!(
            sig.data_check(&buf, &mut recovery),
            DataCheckResult::Stop(106)
        );
    }
}
