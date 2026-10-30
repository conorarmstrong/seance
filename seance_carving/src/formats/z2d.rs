use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ZeroCad (Z2D) carving signature. Header: registered magic {0xc3,0x40} at offset 0x28, plus a
/// fixed pattern of
/// float constants at offsets 0x28..0x4a. No footer or embedded size.
struct Z2dSignature;

const Z2D_MAGIC: &[u8] = &[0xc3, 0x40];

impl FileSignature for Z2dSignature {
    fn name(&self) -> &str {
        "Z2D"
    }

    fn extensions(&self) -> &[&str] {
        &["z2d"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x4a
            && buf[0x28] == 0xc3
            && buf[0x29] == 0x40
            && buf[0x30] == 0xc3
            && buf[0x31] == 0x40
            && buf[0x38] == 0xbf
            && buf[0x39] == 0x40
            && buf[0x40] == 0xbf
            && buf[0x41] == 0x40
            && buf[0x48] == 0xb7
            && buf[0x49] == 0x40
        {
            Some(RecoveryInit {
                min_filesize: 0x4a,
                extension: "z2d".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0x28, Z2D_MAGIC, Arc::new(Z2dSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_z2d_header_match() {
        let sig = Z2dSignature;
        let mut buf = vec![0u8; 0x4a];
        buf[0x28] = 0xc3;
        buf[0x29] = 0x40;
        buf[0x30] = 0xc3;
        buf[0x31] = 0x40;
        buf[0x38] = 0xbf;
        buf[0x39] = 0x40;
        buf[0x40] = 0xbf;
        buf[0x41] = 0x40;
        buf[0x48] = 0xb7;
        buf[0x49] = 0x40;
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_z2d_no_match() {
        let sig = Z2dSignature;
        // All zero buffer: none of the constants present.
        assert!(sig.header_check(&[0u8; 0x4a], 0).is_none());
        // Too short.
        assert!(sig.header_check(&[0xc3, 0x40], 0).is_none());
    }
}
