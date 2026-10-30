use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// TurboTax carving signature. Header at offset 0: "TTFN" 0x01 0x01. No footer; header check only.
const TAX_MAGIC: [u8; 6] = [b'T', b'T', b'F', b'N', 0x01, 0x01];

struct TaxSignature;

impl FileSignature for TaxSignature {
    fn name(&self) -> &str {
        "TurboTax"
    }
    fn extensions(&self) -> &[&str] {
        &["tax"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= TAX_MAGIC.len() && buf[..TAX_MAGIC.len()] == TAX_MAGIC {
            Some(RecoveryInit {
                min_filesize: TAX_MAGIC.len() as u64,
                extension: "tax".to_string(),
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
    registry.register(0, &TAX_MAGIC, Arc::new(TaxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tax_header_match() {
        let sig = TaxSignature;
        assert!(sig.header_check(b"TTFN\x01\x01rest", 0).is_some());
    }

    #[test]
    fn test_tax_no_match() {
        let sig = TaxSignature;
        assert!(sig.header_check(b"TTFN\x02\x01", 0).is_none());
        assert!(sig.header_check(b"NOTTAX", 0).is_none());
    }
}
