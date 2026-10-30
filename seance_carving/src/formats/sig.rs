use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Custom user signatures.
/// NOTE: file_sig.c has no built-in magic bytes. It is a runtime loader that
/// reads a user-supplied `photorec.sig` file and registers those user-defined
/// signatures dynamically. There is nothing static to carve, so `register`
/// intentionally adds no pattern and `header_check` always returns `None`.
/// Porting the runtime signature-file parser is out of scope for the static
/// carving engine.
struct SigSignature;

impl FileSignature for SigSignature {
    fn name(&self) -> &str {
        "Custom Signature"
    }
    fn extensions(&self) -> &[&str] {
        &["custom"]
    }

    fn header_check(&self, _buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // No built-in magic: user signatures are loaded at runtime by PhotoRec.
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(_registry: &mut SignatureRegistry) {
    // No-op: file_sig.c registers only user-defined signatures loaded at runtime
    // from a photorec.sig file. There are no fixed magic bytes to register here.
    // A signature instance exists for completeness but is intentionally never
    // bound to a pattern.
    let _unregistered = Arc::new(SigSignature);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_header_match() {
        // The custom-signature loader has no static magic, so nothing matches.
        let sig = SigSignature;
        assert!(sig.header_check(b"any arbitrary content here", 0).is_none());
    }

    #[test]
    fn test_sig_no_match() {
        let sig = SigSignature;
        assert!(sig.header_check(&[], 0).is_none());
        assert!(sig.header_check(&[0xff; 64], 0).is_none());
    }
}
