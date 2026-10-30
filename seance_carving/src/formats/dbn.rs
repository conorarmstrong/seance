use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DriftBox (DBN) carving signature. Header: ASCII "File created on " at offset 0; PhotoRec
/// additionally requires
/// the marker "[HEADER]" somewhere in the first 512 bytes. No footer.
struct DbnSignature;

impl FileSignature for DbnSignature {
    fn name(&self) -> &str {
        "DBN"
    }
    fn extensions(&self) -> &[&str] {
        &["dbn"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 16 && &buf[0..16] == b"File created on " {
            let window = &buf[..buf.len().min(512)];
            if window.windows(8).any(|w| w == b"[HEADER]") {
                return Some(RecoveryInit {
                    min_filesize: 24,
                    extension: "dbn".to_string(),
                    calculated_file_size: None,
                });
            }
        }
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

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"File created on ", Arc::new(DbnSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbn_header_match() {
        let buf = b"File created on 2010-01-01\n[HEADER]\nrest of data here....";
        assert!(DbnSignature.header_check(buf, 0).is_some());
    }

    #[test]
    fn test_dbn_no_match() {
        // Correct magic but missing "[HEADER]" marker.
        let buf = b"File created on 2010-01-01\nno marker present here....";
        assert!(DbnSignature.header_check(buf, 0).is_none());
        assert!(DbnSignature
            .header_check(b"wrong magic bytes here", 0)
            .is_none());
    }
}
