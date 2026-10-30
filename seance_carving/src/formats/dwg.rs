use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AutoCAD Drawing (.dwg) carving signature. Header: version string "AC10XX" followed by 5 zero
/// bytes at offset 0, where
/// XX is one of the released format codes (12, 13, 14, 15, 18, 21, 23, 24, 27).
/// header_check does no further validation.
struct DwgSignature;

/// Build an 11-byte DWG magic for a given "AC10XX" version code.
const fn dwg_magic(a: u8, b: u8) -> [u8; 11] {
    [b'A', b'C', b'1', b'0', a, b, 0, 0, 0, 0, 0]
}

impl FileSignature for DwgSignature {
    fn name(&self) -> &str {
        "DWG"
    }

    fn extensions(&self) -> &[&str] {
        &["dwg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic (11 bytes) is matched by the registry; accept unconditionally,
        // matching PhotoRec's header_check_dwg.
        if buf.len() >= 11 {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "dwg".to_string(),
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
        20 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    let versions: [(u8, u8); 9] = [
        (b'1', b'2'),
        (b'1', b'3'),
        (b'1', b'4'),
        (b'1', b'5'),
        (b'1', b'8'),
        (b'2', b'1'),
        (b'2', b'3'),
        (b'2', b'4'),
        (b'2', b'7'),
    ];
    for (a, b) in versions {
        registry.register(0, &dwg_magic(a, b), Arc::new(DwgSignature));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dwg_header_match() {
        let sig = DwgSignature;
        // AC1015 + 5 zero bytes.
        assert!(sig.header_check(&dwg_magic(b'1', b'5'), 0).is_some());
    }

    #[test]
    fn test_dwg_no_match() {
        let sig = DwgSignature;
        // Buffer too short to hold the magic.
        assert!(sig.header_check(b"AC10", 0).is_none());
    }
}
