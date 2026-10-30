use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Canon catalog (CTG) carving signature. Header: ":\DCIM\" at byte offset 1 (7 bytes). No footer.
/// Max size 4634 (PhotoRec).
const CTG_MAGIC: &[u8] = b":\\DCIM\\";

struct CtgSignature;

impl FileSignature for CtgSignature {
    fn name(&self) -> &str {
        "CTG"
    }
    fn extensions(&self) -> &[&str] {
        &["ctg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic is registered at offset 1; the buffer starts at the file start.
        if buf.len() >= 8 && &buf[1..8] == CTG_MAGIC {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "ctg".to_string(),
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
        4634
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(1, CTG_MAGIC, Arc::new(CtgSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctg_header_match() {
        let buf = [0x00, b':', b'\\', b'D', b'C', b'I', b'M', b'\\'];
        assert!(CtgSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_ctg_no_match() {
        // Magic present at offset 0 instead of 1 -> None
        let buf = [b':', b'\\', b'D', b'C', b'I', b'M', b'\\', 0x00];
        assert!(CtgSignature.header_check(&buf, 0).is_none());
        assert!(CtgSignature.header_check(b"XXXXXXXX", 0).is_none());
    }
}
