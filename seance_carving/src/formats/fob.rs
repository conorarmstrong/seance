use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Microsoft Dynamics NAV (Navision) object export (FOB) carving signature.
/// The file begins with an object keyword (e.g. "Codeunit ", "Table "), and header_check requires
/// the "NAVNL" or
/// "NAVW" marker to appear somewhere in the buffer to confirm the format.
/// No footer; carves to the next header or max size.
struct FobSignature;

/// First occurrence of `needle` in `haystack`, mirroring td_memmem.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

impl FileSignature for FobSignature {
    fn name(&self) -> &str {
        "FOB"
    }
    fn extensions(&self) -> &[&str] {
        &["fob"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let pos1 = find_sub(buf, b"NAVNL");
        let pos2 = find_sub(buf, b"NAVW");
        if pos1.is_none() && pos2.is_none() {
            return None;
        }
        let mut tmp = 0usize;
        if let Some(p) = pos1 {
            tmp = p;
        }
        if let Some(p) = pos2 {
            if p > tmp {
                tmp = p;
            }
        }
        Some(RecoveryInit {
            min_filesize: tmp as u64,
            extension: "fob".to_string(),
            calculated_file_size: None,
        })
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
    let sig = Arc::new(FobSignature);
    registry.register(0, b"Codeunit ", sig.clone());
    registry.register(0, b"Dataport ", sig.clone());
    registry.register(0, b"Form ", sig.clone());
    registry.register(0, b"MenuSuite ", sig.clone());
    registry.register(0, b"Report ", sig.clone());
    registry.register(0, b"Table ", sig.clone());
    registry.register(0, b"XMLport ", sig);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fob_header_match() {
        let sig = FobSignature;
        let buf = b"Table 50000 MyTable\r\n  NAVW16.0\r\n";
        let init = sig.header_check(buf, 0).expect("should match");
        assert!(init.min_filesize > 0);
    }

    #[test]
    fn test_fob_no_match() {
        let sig = FobSignature;
        // Keyword present but no NAV marker.
        assert!(sig.header_check(b"Codeunit 1 SomeCode", 0).is_none());
    }
}
