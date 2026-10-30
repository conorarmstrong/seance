use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// SPSS saved-data carving signature. Header at offset 0: "$FL2@(#) SPSS DATA FILE" (record type +
/// product name).
/// No footer; header check only.
const SPSS_MAGIC: &[u8] = b"$FL2@(#) SPSS DATA FILE";

struct SpssSignature;

impl FileSignature for SpssSignature {
    fn name(&self) -> &str {
        "SPSS"
    }
    fn extensions(&self) -> &[&str] {
        &["sav"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SPSS_MAGIC.len() && &buf[..SPSS_MAGIC.len()] == SPSS_MAGIC {
            Some(RecoveryInit {
                min_filesize: SPSS_MAGIC.len() as u64,
                extension: "sav".to_string(),
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
    registry.register(0, SPSS_MAGIC, Arc::new(SpssSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spss_header_match() {
        let sig = SpssSignature;
        assert!(sig
            .header_check(b"$FL2@(#) SPSS DATA FILE extra", 0)
            .is_some());
    }

    #[test]
    fn test_spss_no_match() {
        let sig = SpssSignature;
        assert!(sig.header_check(b"$FL2@(#) EXCEL DATA FILE", 0).is_none());
        assert!(sig.header_check(b"NOTSPSS", 0).is_none());
    }
}
