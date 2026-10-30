use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft Jet DB / Sage Simply Accounting database carving signature.
/// Header: 20 bytes at offset 0: 00 01 00 00 "Jet System DB " 00. No footer; min_filesize not set
/// by source.
struct SdwSignature;

const SDW_MAGIC: &[u8] = b"\x00\x01\x00\x00Jet System DB  \x00";

impl FileSignature for SdwSignature {
    fn name(&self) -> &str {
        "Microsoft Jet DB"
    }
    fn extensions(&self) -> &[&str] {
        &["sdw"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SDW_MAGIC.len() && &buf[0..SDW_MAGIC.len()] == SDW_MAGIC {
            Some(RecoveryInit {
                min_filesize: SDW_MAGIC.len() as u64,
                extension: "sdw".to_string(),
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
    registry.register(0, SDW_MAGIC, Arc::new(SdwSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdw_header_match() {
        let sig = SdwSignature;
        assert!(sig.header_check(SDW_MAGIC, 0).is_some());
    }

    #[test]
    fn test_sdw_no_match() {
        let sig = SdwSignature;
        assert!(sig
            .header_check(b"\x00\x01\x00\x00Not System DB  \x00", 0)
            .is_none());
        assert!(sig.header_check(b"\x00\x01", 0).is_none());
    }
}
