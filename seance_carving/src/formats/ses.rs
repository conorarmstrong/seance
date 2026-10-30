use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Cool Edit / Adobe Audition session carving signature. Ported from
/// PhotoRec file_ses.c. Header: "COOLNESS" (8 bytes) at offset 0. No footer.
struct SesSignature;

const SES_MAGIC: &[u8] = b"COOLNESS";

impl FileSignature for SesSignature {
    fn name(&self) -> &str {
        "Cool Edit/Adobe Audition session"
    }
    fn extensions(&self) -> &[&str] {
        &["ses"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= SES_MAGIC.len() && &buf[0..SES_MAGIC.len()] == SES_MAGIC {
            Some(RecoveryInit {
                min_filesize: SES_MAGIC.len() as u64,
                extension: "ses".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, SES_MAGIC, Arc::new(SesSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ses_header_match() {
        let sig = SesSignature;
        assert!(sig.header_check(b"COOLNESS\x00\x00", 0).is_some());
    }

    #[test]
    fn test_ses_no_match() {
        let sig = SesSignature;
        assert!(sig.header_check(b"COOLNES!", 0).is_none());
        assert!(sig.header_check(b"COOL", 0).is_none());
    }
}
