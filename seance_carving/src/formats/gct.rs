use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// XFI Electronic Fuel Injection carving signature. Header: ASCII "JLGEN2XFI" at offset 0. The
/// header encodes a
/// fixed file size of 2416 bytes (data_check_size / file_check_size).
struct GctSignature;

const GCT_MAGIC: &[u8] = b"JLGEN2XFI";

impl FileSignature for GctSignature {
    fn name(&self) -> &str {
        "XFI Electronic Fuel Injection"
    }
    fn extensions(&self) -> &[&str] {
        &["gct"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= GCT_MAGIC.len() && &buf[0..GCT_MAGIC.len()] == GCT_MAGIC {
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "gct".to_string(),
                calculated_file_size: Some(2416),
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
    registry.register(0, GCT_MAGIC, Arc::new(GctSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gct_header_match() {
        let sig = GctSignature;
        let init = sig.header_check(b"JLGEN2XFIrest", 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(2416));
    }

    #[test]
    fn test_gct_no_match() {
        let sig = GctSignature;
        assert!(sig.header_check(b"JLGEN2XXX", 0).is_none());
        assert!(sig.header_check(b"JLGEN", 0).is_none());
    }
}
