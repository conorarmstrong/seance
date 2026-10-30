use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Agelong Tree Database / Abs0luteDatabase carving signature.
/// Header: "ABS0LUTEDATABASE" at offset 0 (16 bytes). No footer; max-size cutoff.
struct AtdSignature;

const ATD_MAGIC: &[u8] = b"ABS0LUTEDATABASE";

impl FileSignature for AtdSignature {
    fn name(&self) -> &str {
        "ATD"
    }
    fn extensions(&self) -> &[&str] {
        &["atd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= ATD_MAGIC.len() && &buf[0..ATD_MAGIC.len()] == ATD_MAGIC {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "atd".to_string(),
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
    registry.register(0, ATD_MAGIC, Arc::new(AtdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atd_header_match() {
        let sig = AtdSignature;
        let mut buf = ATD_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_atd_no_match() {
        let sig = AtdSignature;
        // "ABSOLUTE..." with letter O instead of digit 0.
        assert!(sig.header_check(b"ABSOLUTEDATABASE", 0).is_none());
        // Too short.
        assert!(sig.header_check(b"ABS0LUTE", 0).is_none());
    }
}
