use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WKS (Lotus 1-2-3) carving signature. Ported from file_wks.c.
/// Two headers at offset 0: the 10-byte Lotus BOF record -> "wks", and the 8-byte
/// Lotus/Symphony variant -> "wk4". No footer, minimum-size only.
struct WksSignature;

const WKS_MAGIC: &[u8] = &[0x00, 0x00, 0x02, 0x00, 0x04, 0x04, 0x06, 0x00, 0x08, 0x00];
const WK4_MAGIC: &[u8] = &[0x00, 0x00, 0x1a, 0x00, 0x02, 0x10, 0x04, 0x00];

impl FileSignature for WksSignature {
    fn name(&self) -> &str {
        "WKS"
    }
    fn extensions(&self) -> &[&str] {
        &["wks", "wk4"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= WKS_MAGIC.len() && &buf[..WKS_MAGIC.len()] == WKS_MAGIC {
            return Some(RecoveryInit {
                min_filesize: WKS_MAGIC.len() as u64,
                extension: "wks".to_string(),
                calculated_file_size: None,
            });
        }
        if buf.len() >= WK4_MAGIC.len() && &buf[..WK4_MAGIC.len()] == WK4_MAGIC {
            return Some(RecoveryInit {
                min_filesize: WK4_MAGIC.len() as u64,
                extension: "wk4".to_string(),
                calculated_file_size: None,
            });
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
    registry.register(0, WKS_MAGIC, Arc::new(WksSignature));
    registry.register(0, WK4_MAGIC, Arc::new(WksSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wks_header_match() {
        let sig = WksSignature;
        let wks = sig.header_check(WKS_MAGIC, 0).unwrap();
        assert_eq!(wks.extension, "wks");
        let wk4 = sig.header_check(WK4_MAGIC, 0).unwrap();
        assert_eq!(wk4.extension, "wk4");
    }

    #[test]
    fn test_wks_no_match() {
        let sig = WksSignature;
        assert!(sig.header_check(&[0x00, 0x00, 0xff, 0x00], 0).is_none());
        assert!(sig.header_check(b"", 0).is_none());
    }
}
