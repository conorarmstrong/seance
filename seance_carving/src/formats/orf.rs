use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Olympus Raw Format (ORF) carving signature. Header: "IIRS\x08\x00\x00\x00" or
/// "IIRO\x08\x00\x00\x00" (8 bytes) at offset 0.
/// The IIRO variant is a TIFF-LE container; PhotoRec uses file_check_tiff_le for
/// its footer/size. Degraded here to a header-only match (no footer scan).
struct OrfSignature;

const ORF_MAGIC_IIRS: &[u8] = b"IIRS\x08\x00\x00\x00";
const ORF_MAGIC_IIRO: &[u8] = b"IIRO\x08\x00\x00\x00";

impl FileSignature for OrfSignature {
    fn name(&self) -> &str {
        "ORF"
    }

    fn extensions(&self) -> &[&str] {
        &["orf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && (&buf[0..8] == ORF_MAGIC_IIRS || &buf[0..8] == ORF_MAGIC_IIRO) {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "orf".to_string(),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, ORF_MAGIC_IIRS, Arc::new(OrfSignature));
    registry.register(0, ORF_MAGIC_IIRO, Arc::new(OrfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orf_header_match() {
        let sig = OrfSignature;
        assert!(sig.header_check(ORF_MAGIC_IIRS, 0).is_some());
        assert!(sig.header_check(ORF_MAGIC_IIRO, 0).is_some());
    }

    #[test]
    fn test_orf_no_match() {
        let sig = OrfSignature;
        assert!(sig.header_check(b"IIRX\x08\x00\x00\x00", 0).is_none());
        assert!(sig.header_check(b"IIR", 0).is_none());
    }
}
