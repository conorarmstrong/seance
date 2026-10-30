use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Outlook Nickfile (NK2) carving signature. Header: 8-byte magic `0D F0 AD BA 0A 00 00 00` at
/// offset 0. No footer; the
/// original file_check walks item/entry records to size the file. That stateful
/// record walk is not implemented (see note); we recover via header magic + max size.
struct Nk2Signature;

const NK2_MAGIC: [u8; 8] = [0x0d, 0xf0, 0xad, 0xba, 0x0a, 0x00, 0x00, 0x00];

impl FileSignature for Nk2Signature {
    fn name(&self) -> &str {
        "NK2"
    }
    fn extensions(&self) -> &[&str] {
        &["nk2"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && buf[0..8] == NK2_MAGIC {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "nk2".to_string(),
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
        100 * 1024 * 1024 // NK2_MAX_FILESIZE from PhotoRec
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &NK2_MAGIC, Arc::new(Nk2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nk2_header_match() {
        let sig = Nk2Signature;
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&NK2_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_nk2_no_match() {
        let sig = Nk2Signature;
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
        assert!(sig.header_check(b"\x0d\xf0\xad", 0).is_none());
    }
}
