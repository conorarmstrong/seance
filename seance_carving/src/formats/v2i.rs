use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Symantec v2i backup image carving signature. Header: "$CAN" at offset 0 plus the signature 0x13
/// 0x04 0x08
/// 0x00 at offset 0x14. No footer.
struct V2iSignature;

const V2I_MAGIC: &[u8] = b"$CAN";
const V2I_SIGN: &[u8] = &[0x13, 0x04, 0x08, 0x00];

impl FileSignature for V2iSignature {
    fn name(&self) -> &str {
        "v2i Backup"
    }
    fn extensions(&self) -> &[&str] {
        &["v2i"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x18 && &buf[0..4] == V2I_MAGIC && &buf[0x14..0x18] == V2I_SIGN {
            Some(RecoveryInit {
                min_filesize: 0x18,
                extension: "v2i".to_string(),
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
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, V2I_MAGIC, Arc::new(V2iSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x18];
        buf[0..4].copy_from_slice(V2I_MAGIC);
        buf[0x14..0x18].copy_from_slice(V2I_SIGN);
        buf
    }

    #[test]
    fn test_v2i_header_match() {
        assert!(V2iSignature.header_check(&make_buf(), 0).is_some());
    }

    #[test]
    fn test_v2i_no_match() {
        // secondary signature wrong
        let mut buf = make_buf();
        buf[0x14] = 0x00;
        assert!(V2iSignature.header_check(&buf, 0).is_none());
        // magic wrong
        let mut buf2 = make_buf();
        buf2[0] = b'X';
        assert!(V2iSignature.header_check(&buf2, 0).is_none());
        // too short
        assert!(V2iSignature.header_check(b"$CAN", 0).is_none());
    }
}
