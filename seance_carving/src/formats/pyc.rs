use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Python Compiled Script (PYC) carving signature. Header: one of 14 version magic words (4 bytes)
/// at offset 0, followed by a 4-byte
/// modtime, then a marshalled TYPE_CODE object ('c', 0, 0, 0) at offset 8. No footer.
struct PycSignature;

const PYC_MAGICS: &[[u8; 4]] = &[
    [0x99, 0x4e, 0x0d, 0x0a],
    [0x87, 0xc6, 0x0d, 0x0a],
    [0x2a, 0xeb, 0x0d, 0x0a],
    [0x2d, 0xed, 0x0d, 0x0a],
    [0x3b, 0xf2, 0x0d, 0x0a],
    [0x6d, 0xf2, 0x0d, 0x0a],
    [0xb3, 0xf2, 0x0d, 0x0a],
    [0xd1, 0xf2, 0x0d, 0x0a],
    [0x03, 0xf3, 0x0d, 0x0a],
    [0x3b, 0x0c, 0x0d, 0x0a],
    [0x4f, 0x0c, 0x0d, 0x0a],
    [0x6c, 0x0c, 0x0d, 0x0a],
    [0x9e, 0x0c, 0x0d, 0x0a],
    [0xee, 0x0c, 0x0d, 0x0a],
];

impl FileSignature for PycSignature {
    fn name(&self) -> &str {
        "PYC"
    }

    fn extensions(&self) -> &[&str] {
        &["pyc"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Marshalled code object must be TYPE_CODE with argcount < 256.
        if buf.len() < 12 {
            return None;
        }
        if buf[8] != b'c' || buf[9] != 0 || buf[10] != 0 || buf[11] != 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 12,
            extension: "pyc".to_string(),
            calculated_file_size: None,
        })
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
    for magic in PYC_MAGICS {
        registry.register(0, magic, Arc::new(PycSignature));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pyc_header_match() {
        let sig = PycSignature;
        // magic + modtime + 'c',0,0,0
        let buf = [0x03, 0xf3, 0x0d, 0x0a, 0, 0, 0, 0, b'c', 0, 0, 0];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_pyc_no_match() {
        let sig = PycSignature;
        // Wrong marshalled type byte at offset 8.
        let buf = [0x03, 0xf3, 0x0d, 0x0a, 0, 0, 0, 0, b'x', 0, 0, 0];
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short.
        assert!(sig.header_check(&[0x03, 0xf3, 0x0d, 0x0a], 0).is_none());
    }
}
