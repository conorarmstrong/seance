use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Terraria Player File carving signature. Header: 16-byte fixed magic at offset 0. Fixed size 1856
/// bytes (calculated). No footer.
struct PlrSignature;

const PLR_MAGIC: &[u8] = &[
    0x0f, b'w', b'g', 0xfe, 0xb1, b'J', 0xb2, 0xef, 0xfc, b'j', 0x9b, b'K', b'x', 0x5b, 0xf4, b'V',
];

impl FileSignature for PlrSignature {
    fn name(&self) -> &str {
        "Terraria Player File"
    }
    fn extensions(&self) -> &[&str] {
        &["plr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= PLR_MAGIC.len() && &buf[0..PLR_MAGIC.len()] == PLR_MAGIC {
            Some(RecoveryInit {
                min_filesize: 1856,
                extension: "plr".to_string(),
                calculated_file_size: Some(1856),
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
    registry.register(0, PLR_MAGIC, Arc::new(PlrSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plr_header_match() {
        let sig = PlrSignature;
        let mut buf = Vec::from(PLR_MAGIC);
        buf.push(0x00);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(1856));
    }

    #[test]
    fn test_plr_no_match() {
        let sig = PlrSignature;
        let mut buf = Vec::from(PLR_MAGIC);
        buf[0] = 0x00;
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"\x0fwg", 0).is_none());
    }
}
