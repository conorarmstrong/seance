use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft ITOL/ITLS (LIT e-book) carving signature.
/// Header: "ITOLITLS" + 01 00 00 00 (12 bytes) at offset 0. No footer.
struct LitSignature;

impl FileSignature for LitSignature {
    fn name(&self) -> &str {
        "Microsoft ITOL/ITLS"
    }
    fn extensions(&self) -> &[&str] {
        &["lit"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        const MAGIC: &[u8] = &[
            b'I', b'T', b'O', b'L', b'I', b'T', b'L', b'S', 0x01, 0x00, 0x00, 0x00,
        ];
        if buf.len() >= 12 && &buf[0..12] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 12,
                extension: "lit".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[
            b'I', b'T', b'O', b'L', b'I', b'T', b'L', b'S', 0x01, 0x00, 0x00, 0x00,
        ],
        Arc::new(LitSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lit_header_match() {
        let sig = LitSignature;
        assert!(sig.header_check(b"ITOLITLS\x01\x00\x00\x00", 0).is_some());
    }

    #[test]
    fn test_lit_no_match() {
        let sig = LitSignature;
        assert!(sig.header_check(b"ITOLITLS\x02\x00\x00\x00", 0).is_none());
        assert!(sig.header_check(b"NOTLIT", 0).is_none());
    }
}
