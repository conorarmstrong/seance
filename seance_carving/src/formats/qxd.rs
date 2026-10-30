use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// QuarkXpress document carving signature. Header: "XPR3" at offset 0 (.qxd), or "IIXPR3"/"MMXPR3"
/// at offset 2 (.qxp).
/// No footer; PhotoRec only enforces a minimum size.
struct QxdSignature;

impl FileSignature for QxdSignature {
    fn name(&self) -> &str {
        "QuarkXpress"
    }
    fn extensions(&self) -> &[&str] {
        &["qxd", "qxp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // XPR3 at offset 0 -> QuarkXpress Document (.qxd)
        if buf.len() >= 4 && &buf[0..4] == b"XPR3" {
            return Some(RecoveryInit {
                min_filesize: 4,
                extension: "qxd".to_string(),
                calculated_file_size: None,
            });
        }
        // "IIXPR3" / "MMXPR3" at offset 2 -> QuarkXpress Project (.qxp)
        if buf.len() >= 8 && (&buf[2..4] == b"II" || &buf[2..4] == b"MM") && &buf[4..8] == b"XPR3" {
            return Some(RecoveryInit {
                min_filesize: 8,
                extension: "qxp".to_string(),
                calculated_file_size: None,
            });
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn weak_header(&self) -> bool {
        // No public layout past the magic and no real sample is held, so the
        // magic alone must never split a running carve (CARVE-015).
        true
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"XPR3", Arc::new(QxdSignature));
    registry.register(2, b"IIXPR3", Arc::new(QxdSignature));
    registry.register(2, b"MMXPR3", Arc::new(QxdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qxd_header_match() {
        let sig = QxdSignature;
        // XPR3 -> qxd
        let init = sig.header_check(b"XPR3\x00\x00\x00\x00", 0).unwrap();
        assert_eq!(init.extension, "qxd");
        // IIXPR3 at offset 2 -> qxp
        let init = sig.header_check(b"\x00\x00IIXPR3", 0).unwrap();
        assert_eq!(init.extension, "qxp");
        // MMXPR3 at offset 2 -> qxp
        let init = sig.header_check(b"\x00\x00MMXPR3", 0).unwrap();
        assert_eq!(init.extension, "qxp");
    }

    #[test]
    fn test_qxd_no_match() {
        let sig = QxdSignature;
        assert!(sig.header_check(b"NOPE\x00\x00\x00\x00", 0).is_none());
        assert!(sig.header_check(b"\x00\x00ZZXPR3", 0).is_none());
        assert!(sig.header_check(b"XP", 0).is_none());
    }
}
