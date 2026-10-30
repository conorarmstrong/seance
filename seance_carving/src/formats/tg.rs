use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Tux Guitar (TG) carving signature. Header: 0x1b 0x00 followed by UTF-16LE
/// "TuxGuitar File Format - 1.2" at offset 0 (56-byte magic). No footer.
struct TgSignature;

const TG_MAGIC: &[u8] = &[
    0x1b, 0x00, b'T', 0x00, b'u', 0x00, b'x', 0x00, b'G', 0x00, b'u', 0x00, b'i', 0x00, b't', 0x00,
    b'a', 0x00, b'r', 0x00, b' ', 0x00, b'F', 0x00, b'i', 0x00, b'l', 0x00, b'e', 0x00, b' ', 0x00,
    b'F', 0x00, b'o', 0x00, b'r', 0x00, b'm', 0x00, b'a', 0x00, b't', 0x00, b' ', 0x00, 0x2d, 0x00,
    b' ', 0x00, b'1', 0x00, b'.', 0x00, b'2', 0x00,
];

impl FileSignature for TgSignature {
    fn name(&self) -> &str {
        "Tux Guitar"
    }
    fn extensions(&self) -> &[&str] {
        &["tg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= TG_MAGIC.len() && &buf[0..TG_MAGIC.len()] == TG_MAGIC {
            Some(RecoveryInit {
                min_filesize: TG_MAGIC.len() as u64,
                extension: "tg".to_string(),
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
    registry.register(0, TG_MAGIC, Arc::new(TgSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tg_header_match() {
        let mut buf = TG_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(TgSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_tg_no_match() {
        let mut buf = TG_MAGIC.to_vec();
        buf[0] = 0x00;
        assert!(TgSignature.header_check(&buf, 0).is_none());
        assert!(TgSignature.header_check(b"TG", 0).is_none());
    }
}
