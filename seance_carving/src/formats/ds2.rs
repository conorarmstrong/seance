use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Digital Speech Standard v2 (.ds2) carving signature. Ported from file_ds2.c.
/// Header: magic {0x03,'d','s','2'} at offset 0, followed by 24 ASCII digits at
/// offset 0x26 (the creation/complete date fields). Minimum file size 0x200.
struct Ds2Signature;

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

impl FileSignature for Ds2Signature {
    fn name(&self) -> &str {
        "DS2"
    }

    fn extensions(&self) -> &[&str] {
        &["ds2"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x26 + 24
            && buf[0] == 0x03
            && &buf[1..4] == b"ds2"
            && buf[0x26..0x26 + 24].iter().all(|&b| is_digit(b))
        {
            Some(RecoveryInit {
                min_filesize: 0x200,
                extension: "ds2".to_string(),
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
    registry.register(0, &[0x03, b'd', b's', b'2'], Arc::new(Ds2Signature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> Vec<u8> {
        let mut buf = vec![0u8; 0x26 + 24];
        buf[0..4].copy_from_slice(&[0x03, b'd', b's', b'2']);
        for b in buf.iter_mut().skip(0x26).take(24) {
            *b = b'0';
        }
        buf
    }

    #[test]
    fn test_ds2_header_match() {
        let sig = Ds2Signature;
        assert!(sig.header_check(&make_header(), 0).is_some());
    }

    #[test]
    fn test_ds2_no_match() {
        let sig = Ds2Signature;
        // Non-digit in date region.
        let mut buf = make_header();
        buf[0x26] = b'X';
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let mut buf2 = make_header();
        buf2[0] = 0x02;
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
