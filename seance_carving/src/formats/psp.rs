use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Paint Shop Pro Image File (PSP) carving signature. Header: "Paint Shop Pro Image
/// File\n\x1a\0\0\0\0\0" at offset 0, plus a "~BK\0"
/// block marker at offset 0x24. The C data_check walks the ~BK chunk list to compute
/// the exact size; that stateful walk is degraded here to a header-magic + max-size
/// carve (see note).
struct PspSignature;

const PSP_MAGIC: &[u8] = b"Paint Shop Pro Image File\n\x1a\x00\x00\x00\x00\x00";

impl FileSignature for PspSignature {
    fn name(&self) -> &str {
        "PSP"
    }

    fn extensions(&self) -> &[&str] {
        &["psp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need the 32-byte magic plus the "~BK\0" marker at 0x24.
        if buf.len() < 0x28 {
            return None;
        }
        if &buf[..PSP_MAGIC.len()] != PSP_MAGIC {
            return None;
        }
        if &buf[0x24..0x28] != b"~BK\x00" {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x28,
            extension: "psp".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, PSP_MAGIC, Arc::new(PspSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psp_header_match() {
        let sig = PspSignature;
        let mut buf = vec![0u8; 0x28];
        buf[..PSP_MAGIC.len()].copy_from_slice(PSP_MAGIC);
        buf[0x24..0x28].copy_from_slice(b"~BK\x00");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_psp_no_match() {
        let sig = PspSignature;
        let mut buf = vec![0u8; 0x28];
        buf[..PSP_MAGIC.len()].copy_from_slice(PSP_MAGIC);
        // Missing ~BK marker at 0x24.
        assert!(sig.header_check(&buf, 0).is_none());
        // Too short.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
    }
}
