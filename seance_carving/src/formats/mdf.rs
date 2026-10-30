use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft SQL Server Master Database File (MDF) carving signature.
/// Header: magic {0x01,0x0f,0x00,0x00} at offset 0, plus a fixed byte pattern
/// through offset 0x1b. No footer.
struct MdfSignature;

const MDF_MAGIC: &[u8] = &[0x01, 0x0f, 0x00, 0x00];

impl FileSignature for MdfSignature {
    fn name(&self) -> &str {
        "MDF"
    }
    fn extensions(&self) -> &[&str] {
        &["mdf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x1c
            && buf[0x00] == 0x01
            && buf[0x01] == 0x0f
            && buf[0x02] == 0x00
            && buf[0x03] == 0x00
            && buf[0x08..0x16].iter().all(|&b| b == 0x00)
            && buf[0x16] == 0x01
            && buf[0x17] == 0x00
            && buf[0x18] == 0x63
            && buf[0x19] == 0x00
            && buf[0x1a] == 0x00
            && buf[0x1b] == 0x00
        {
            Some(RecoveryInit {
                min_filesize: 0x1c,
                extension: "mdf".to_string(),
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
    registry.register(0, MDF_MAGIC, Arc::new(MdfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x1c];
        buf[0x00] = 0x01;
        buf[0x01] = 0x0f;
        buf[0x16] = 0x01;
        buf[0x18] = 0x63;
        buf
    }

    #[test]
    fn test_mdf_header_match() {
        let sig = MdfSignature;
        assert!(sig.header_check(&make_buf(), 0).is_some());
    }

    #[test]
    fn test_mdf_no_match() {
        let sig = MdfSignature;
        // Missing the 0x63 sentinel.
        let mut buf = make_buf();
        buf[0x18] = 0x00;
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let mut buf2 = make_buf();
        buf2[0x01] = 0x00;
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
