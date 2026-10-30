use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// QEMU copy-on-write disk image carving signature. Header: "QFI" FB 00 00 00 VV at offset 0, where
/// VV is version 1, 2 or 3.
/// No footer. PhotoRec computes min_filesize from big-endian header offsets
/// (l1/refcount/snapshot tables); that computation is degraded here to a fixed
/// minimum.
struct CowSignature;

impl FileSignature for CowSignature {
    fn name(&self) -> &str {
        "QEMU QCOW Image"
    }
    fn extensions(&self) -> &[&str] {
        &["cow"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8
            && &buf[0..4] == b"QFI\xfb"
            && buf[4] == 0x00
            && buf[5] == 0x00
            && buf[6] == 0x00
            && (buf[7] == 0x01 || buf[7] == 0x02 || buf[7] == 0x03)
        {
            Some(RecoveryInit {
                min_filesize: 512,
                extension: "cow".to_string(),
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
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"QFI\xfb\x00\x00\x00\x01", Arc::new(CowSignature));
    registry.register(0, b"QFI\xfb\x00\x00\x00\x02", Arc::new(CowSignature));
    registry.register(0, b"QFI\xfb\x00\x00\x00\x03", Arc::new(CowSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cow_header_match() {
        let sig = CowSignature;
        assert!(sig.header_check(b"QFI\xfb\x00\x00\x00\x01", 0).is_some());
        assert!(sig.header_check(b"QFI\xfb\x00\x00\x00\x02", 0).is_some());
        assert!(sig.header_check(b"QFI\xfb\x00\x00\x00\x03", 0).is_some());
    }

    #[test]
    fn test_cow_no_match() {
        let sig = CowSignature;
        // Unsupported version 4.
        assert!(sig.header_check(b"QFI\xfb\x00\x00\x00\x04", 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(b"XFI\xfb\x00\x00\x00\x01", 0).is_none());
    }
}
