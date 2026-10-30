use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// LUKS encrypted volume carving signature. Header: "LUKS" ba be (6 bytes) at offset 0. Then a
/// big-endian version at
/// offset 6 that must be 1 or 2, and cipherName[0] at offset 8 must be a
/// letter. min_filesize 512. No footer.
struct LuksSignature;

impl FileSignature for LuksSignature {
    fn name(&self) -> &str {
        "LUKS encrypted file"
    }
    fn extensions(&self) -> &[&str] {
        &["luks"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        const MAGIC: &[u8] = &[b'L', b'U', b'K', b'S', 0xba, 0xbe];
        // Need magic (6) + version (2) + cipherName[0] (1) = 9 bytes.
        if buf.len() < 9 || &buf[0..6] != MAGIC {
            return None;
        }
        let version = u16::from_be_bytes([buf[6], buf[7]]);
        if !(1..=2).contains(&version) {
            return None;
        }
        if !buf[8].is_ascii_alphabetic() {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 512,
            extension: "luks".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(
        0,
        &[b'L', b'U', b'K', b'S', 0xba, 0xbe],
        Arc::new(LuksSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luks_header_match() {
        let sig = LuksSignature;
        // version=1 (00 01), cipherName[0]='a'
        let buf = [b'L', b'U', b'K', b'S', 0xba, 0xbe, 0x00, 0x01, b'a'];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_luks_no_match() {
        let sig = LuksSignature;
        // Bad version (0) rejected.
        let bad_ver = [b'L', b'U', b'K', b'S', 0xba, 0xbe, 0x00, 0x00, b'a'];
        assert!(sig.header_check(&bad_ver, 0).is_none());
        // Non-alpha cipherName[0] rejected.
        let bad_cipher = [b'L', b'U', b'K', b'S', 0xba, 0xbe, 0x00, 0x01, 0x00];
        assert!(sig.header_check(&bad_cipher, 0).is_none());
        // Wrong magic rejected.
        assert!(sig.header_check(b"NOTLUKS!!", 0).is_none());
    }
}
