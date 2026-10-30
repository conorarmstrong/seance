use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Digital Speech Standard (.dss) carving signature. Ported from file_dss.c.
/// Header: magic {0x02,'d','s','s'} at offset 0, followed by 24 ASCII digits at
/// offset 0x26 (the creation/complete date fields). Minimum file size 1024.
struct DssSignature;

impl FileSignature for DssSignature {
    fn name(&self) -> &str {
        "DSS"
    }

    fn extensions(&self) -> &[&str] {
        &["dss"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x26 + 24
            && buf[0] == 0x02
            && &buf[1..4] == b"dss"
            && buf[0x26..0x26 + 24].iter().all(|&b| b.is_ascii_digit())
        {
            Some(RecoveryInit {
                min_filesize: 1024,
                extension: "dss".to_string(),
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
    registry.register(0, &[0x02, b'd', b's', b's'], Arc::new(DssSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> Vec<u8> {
        let mut buf = vec![0u8; 0x26 + 24];
        buf[0..4].copy_from_slice(&[0x02, b'd', b's', b's']);
        for b in buf.iter_mut().skip(0x26).take(24) {
            *b = b'9';
        }
        buf
    }

    #[test]
    fn test_dss_header_match() {
        let sig = DssSignature;
        assert!(sig.header_check(&make_header(), 0).is_some());
    }

    #[test]
    fn test_dss_no_match() {
        let sig = DssSignature;
        // Non-digit in date region.
        let mut buf = make_header();
        buf[0x30] = b'Z';
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let mut buf2 = make_header();
        buf2[0] = 0x03;
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
