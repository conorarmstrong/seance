use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// dBase III (DBF) carving signature. Header: 0x03 at offset 0, followed by a plausible YY/MM/DD
/// date and a
/// block of reserved zero bytes. No footer; size grows to the next header.
struct DbfSignature;

impl FileSignature for DbfSignature {
    fn name(&self) -> &str {
        "DBF"
    }
    fn extensions(&self) -> &[&str] {
        &["dbf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // 0x03 YY MM DD reserved=0 (see header_check_dbf)
        if buf.len() >= 32
            && buf[0] == 0x03
            && ((buf[1] > 80 && buf[1] < 120) || buf[1] < 20)
            && (buf[2] >= 1 && buf[2] <= 12)
            && (buf[3] >= 1 && buf[3] <= 31)
            && buf[12..28].iter().all(|&b| b == 0)
            && buf[30] == 0
            && buf[31] == 0
        {
            Some(RecoveryInit {
                min_filesize: 32,
                extension: "dbf".to_string(),
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
    registry.register(0, &[0x03], Arc::new(DbfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbf_header_match() {
        let mut buf = [0u8; 32];
        buf[0] = 0x03;
        buf[1] = 100; // year in range
        buf[2] = 6; // month
        buf[3] = 15; // day
        assert!(DbfSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_dbf_no_match() {
        let buf = [0u8; 32];
        assert!(DbfSignature.header_check(&buf, 0).is_none());
        assert!(DbfSignature.header_check(b"\x03", 0).is_none());
    }
}
