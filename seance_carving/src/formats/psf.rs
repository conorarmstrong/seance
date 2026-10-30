use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Print Shop carving signature. Header: "PSD5RDOC" at offset 12. Size is big-endian u32 at offset
/// 28
/// plus 272 bytes (header + trailer). No footer; size enforced by min check.
struct PsfSignature;

impl FileSignature for PsfSignature {
    fn name(&self) -> &str {
        "PSF"
    }
    fn extensions(&self) -> &[&str] {
        &["psf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 32 && &buf[12..20] == b"PSD5RDOC" {
            let size = ((buf[28] as u64) << 24)
                + ((buf[29] as u64) << 16)
                + ((buf[30] as u64) << 8)
                + (buf[31] as u64)
                + 272;
            Some(RecoveryInit {
                min_filesize: 32,
                extension: "psf".to_string(),
                calculated_file_size: Some(size),
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
    registry.register(12, b"PSD5RDOC", Arc::new(PsfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psf_header_match() {
        let mut buf = vec![0u8; 32];
        buf[12..20].copy_from_slice(b"PSD5RDOC");
        buf[31] = 0x10;
        let init = PsfSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x10 + 272));
    }

    #[test]
    fn test_psf_no_match() {
        let buf = vec![0u8; 32];
        assert!(PsfSignature.header_check(&buf, 0).is_none());
        assert!(PsfSignature.header_check(b"short", 0).is_none());
    }
}
