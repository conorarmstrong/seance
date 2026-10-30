use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Gobe Productive Document (.gp2) carving signature. Header at offset 0: "GOBE SCOTT/01/02DOC!"
/// (20 bytes).
/// Footer: 00 00 00 01 'E' 'N' 'D' '!' (8 bytes).
struct Gp2Signature;

const GP2_MAGIC: &[u8] = b"GOBE SCOTT/01/02DOC!";
const GP2_FOOTER: &[u8] = &[0x00, 0x00, 0x00, 0x01, b'E', b'N', b'D', b'!'];

impl FileSignature for Gp2Signature {
    fn name(&self) -> &str {
        "GP2"
    }
    fn extensions(&self) -> &[&str] {
        &["gp2"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= GP2_MAGIC.len() && &buf[0..GP2_MAGIC.len()] == GP2_MAGIC {
            Some(RecoveryInit {
                min_filesize: 28,
                extension: "gp2".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        match footer_end_spanning(buf, recovery, GP2_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, GP2_MAGIC, Arc::new(Gp2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gp2_header_match() {
        let sig = Gp2Signature;
        assert!(sig.header_check(GP2_MAGIC, 0).is_some());
    }

    #[test]
    fn test_gp2_no_match() {
        let sig = Gp2Signature;
        assert!(sig.header_check(b"GOBE SCOTT/01/02XXX!", 0).is_none());
        assert!(sig.header_check(b"short", 0).is_none());
    }

    #[test]
    fn test_gp2_footer_detection() {
        let sig = Gp2Signature;
        let mut recovery = FileRecovery {
            extension: "gp2".to_string(),
            file_size: 200,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 28,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0xffu8; 5];
        buf.extend_from_slice(GP2_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        // 200 + pos(5) + footer(8) = 213
        assert_eq!(result, DataCheckResult::Stop(213));
    }
}
