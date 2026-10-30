use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft SQL Server Log Data File (LDF) carving signature.
/// Registered magic: 01 0f 00 00 at offset 0. The full header_check validates
/// the first 28 bytes (0x00..0x1c): 01 0f 00 00, zero fill, then 02 at 0x16 and
/// 63 at 0x18. No footer.
struct LdfSignature;

impl FileSignature for LdfSignature {
    fn name(&self) -> &str {
        "MSSQL Log Data File"
    }
    fn extensions(&self) -> &[&str] {
        &["ldf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x1c
            && buf[0x00] == 0x01
            && buf[0x01] == 0x0f
            && buf[0x02] == 0x00
            && buf[0x03] == 0x00
            && buf[0x08] == 0x00
            && buf[0x09] == 0x00
            && buf[0x0a] == 0x00
            && buf[0x0b] == 0x00
            && buf[0x0c] == 0x00
            && buf[0x0d] == 0x00
            && buf[0x0e] == 0x00
            && buf[0x0f] == 0x00
            && buf[0x10] == 0x00
            && buf[0x11] == 0x00
            && buf[0x12] == 0x00
            && buf[0x13] == 0x00
            && buf[0x14] == 0x00
            && buf[0x15] == 0x00
            && buf[0x16] == 0x02
            && buf[0x17] == 0x00
            && buf[0x18] == 0x63
            && buf[0x19] == 0x00
            && buf[0x1a] == 0x00
            && buf[0x1b] == 0x00
        {
            Some(RecoveryInit {
                min_filesize: 0x1c,
                extension: "ldf".to_string(),
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
    registry.register(0, &[0x01, 0x0f, 0x00, 0x00], Arc::new(LdfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> [u8; 0x1c] {
        let mut b = [0u8; 0x1c];
        b[0x00] = 0x01;
        b[0x01] = 0x0f;
        b[0x16] = 0x02;
        b[0x18] = 0x63;
        b
    }

    #[test]
    fn test_ldf_header_match() {
        let sig = LdfSignature;
        assert!(sig.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_ldf_no_match() {
        let sig = LdfSignature;
        // Wrong byte at 0x18 breaks the match.
        let mut bad = valid_header();
        bad[0x18] = 0x00;
        assert!(sig.header_check(&bad, 0).is_none());
        // Short buffer rejected.
        assert!(sig.header_check(&[0x01, 0x0f, 0x00, 0x00], 0).is_none());
    }
}
