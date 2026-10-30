use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// HTTP cache carving signature. Header: literal "HTTP/1.1 200 OK\r\nDate:" (22 bytes) at offset 0.
/// No footer; header_check always accepts on magic match.
struct HttpSignature;

const HTTP_MAGIC: &[u8] = b"HTTP/1.1 200 OK\r\nDate:";

impl FileSignature for HttpSignature {
    fn name(&self) -> &str {
        "HTTP"
    }
    fn extensions(&self) -> &[&str] {
        &["http"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= HTTP_MAGIC.len() && &buf[0..HTTP_MAGIC.len()] == HTTP_MAGIC {
            Some(RecoveryInit {
                min_filesize: 22,
                extension: "http".to_string(),
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
    registry.register(0, HTTP_MAGIC, Arc::new(HttpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_header_match() {
        let sig = HttpSignature;
        assert!(sig
            .header_check(b"HTTP/1.1 200 OK\r\nDate: Mon", 0)
            .is_some());
    }

    #[test]
    fn test_http_no_match() {
        let sig = HttpSignature;
        assert!(sig.header_check(b"HTTP/1.0 200 OK\r\nDate:", 0).is_none());
        assert!(sig.header_check(b"NOTHTTP", 0).is_none());
    }
}
