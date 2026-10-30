use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Macromedia Freehand 10 carving signature. Header: 36-byte object-table prefix ending in
/// "FreeHand10" at offset 0.
/// No footer; min filesize 4096.
struct Fh10Signature;

const MAGIC: [u8; 36] = [
    0x1c, 0x01, 0x00, 0x00, 0x02, 0x00, 0x04, 0x1c, 0x01, 0x14, 0x00, 0x02, 0x00, 0x14, 0x1c, 0x01,
    0x16, 0x00, 0x02, 0x00, 0x08, 0x1c, 0x01, 0x1e, 0x00, 0x0a, 0x46, 0x72, 0x65, 0x65, 0x48, 0x61,
    0x6e, 0x64, 0x31, 0x30,
];

impl FileSignature for Fh10Signature {
    fn name(&self) -> &str {
        "Freehand 10"
    }
    fn extensions(&self) -> &[&str] {
        &["fh10"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 36 && buf[0..36] == MAGIC {
            Some(RecoveryInit {
                min_filesize: 4096,
                extension: "fh10".to_string(),
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
    registry.register(0, &MAGIC, Arc::new(Fh10Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fh10_header_match() {
        let sig = Fh10Signature;
        assert!(sig.header_check(&MAGIC, 0).is_some());
    }

    #[test]
    fn test_fh10_no_match() {
        let sig = Fh10Signature;
        let buf = [0u8; 36];
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&[0x1c, 0x01], 0).is_none());
    }
}
