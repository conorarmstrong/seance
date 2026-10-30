use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Oracle Dump export (DMP) carving signature. Header: 0x03 0x00 0x01 "EXPORT:V" at offset 0,
/// followed by a version digit
/// at byte 11. No footer.
struct DmpSignature;

const DMP_MAGIC: &[u8] = &[
    0x03, 0x00, 0x01, b'E', b'X', b'P', b'O', b'R', b'T', b':', b'V',
];

impl FileSignature for DmpSignature {
    fn name(&self) -> &str {
        "DMP"
    }
    fn extensions(&self) -> &[&str] {
        &["dmp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..11] == DMP_MAGIC && buf[11] >= b'0' && buf[11] <= b'9' {
            Some(RecoveryInit {
                min_filesize: 12,
                extension: "dmp".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, DMP_MAGIC, Arc::new(DmpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dmp_header_match() {
        let mut buf = DMP_MAGIC.to_vec();
        buf.push(b'7'); // version digit
        assert!(DmpSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_dmp_no_match() {
        let mut buf = DMP_MAGIC.to_vec();
        buf.push(b'X'); // not a digit
        assert!(DmpSignature.header_check(&buf, 0).is_none());
        assert!(DmpSignature.header_check(b"\x03\x00\x01EXPO", 0).is_none());
    }
}
