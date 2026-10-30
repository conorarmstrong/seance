use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};

/// The upstream file is PhotoRec's copy-me example: its magic, offset and
/// footer are unfilled macros (HEADER_MAGIC / HEADER_LOC / FOOTER_MAGIC), so
/// there are NO real magic bytes to match. To avoid inventing a false forensic
/// signature, this registers nothing and `header_check` never matches. See
/// `note`.
struct TemplateSignature;

impl FileSignature for TemplateSignature {
    fn name(&self) -> &str {
        "TEMPLATE"
    }
    fn extensions(&self) -> &[&str] {
        &["extension"]
    }

    fn header_check(&self, _buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // No real magic defined in the upstream template; never match.
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
    // No magic bytes exist in the upstream template; intentionally register
    // nothing rather than fabricate a signature.
    let _ = TemplateSignature;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_header_match() {
        // The template has no real magic, so nothing ever matches.
        let sig = TemplateSignature;
        assert!(sig.header_check(b"anything at all", 0).is_none());
    }

    #[test]
    fn test_template_no_match() {
        let mut registry = SignatureRegistry::new();
        register(&mut registry);
        // register() intentionally adds no signatures.
        assert!(registry.is_empty());
    }
}
