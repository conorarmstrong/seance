use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AVCHD Clip Information carving signature. Header: "HDMV0100" at offset 0 (8 bytes). No footer,
/// no encoded size.
const CPI_MAGIC: &[u8] = b"HDMV0100";

struct CpiSignature;

impl FileSignature for CpiSignature {
    fn name(&self) -> &str {
        "CPI"
    }
    fn extensions(&self) -> &[&str] {
        &["cpi"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..8] == CPI_MAGIC {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "cpi".to_string(),
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
    registry.register(0, CPI_MAGIC, Arc::new(CpiSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpi_header_match() {
        assert!(CpiSignature.header_check(b"HDMV0100data", 0).is_some());
    }

    #[test]
    fn test_cpi_no_match() {
        assert!(CpiSignature.header_check(b"HDMV0200", 0).is_none());
        assert!(CpiSignature.header_check(b"XXX", 0).is_none());
    }
}
