use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AxCrypt (.axx) carving signature. Header: guidAxCryptFileIdInverse + length + ePreamble (21
/// bytes at offset 0).
/// PhotoRec's file_check walks the AxCrypt section headers to size the file; that
/// stateful walk is degraded here to a header-magic + min-size check (see note).
struct AxxSignature;

/// 21-byte header magic.
const AXX_HEADER: [u8; 21] = [
    0xc0, 0xb9, 0x07, 0x2e, 0x4f, 0x93, 0xf1, 0x46, 0xa0, 0x15, 0x79, 0x2c, 0xa1, 0xd9, 0xe8, 0x21,
    0x15, 0x00, 0x00, 0x00, 0x02,
];

impl FileSignature for AxxSignature {
    fn name(&self) -> &str {
        "AxCrypt"
    }

    fn extensions(&self) -> &[&str] {
        &["axx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // The first section header sits at offset 0x10 + 0x15 = 0x25 (aoLength u32 LE).
        if buf.len() < 0x25 + 4 || buf[..AXX_HEADER.len()] != AXX_HEADER {
            return None;
        }
        let ao_length = u32::from_le_bytes([buf[0x25], buf[0x26], buf[0x27], buf[0x28]]);
        if ao_length < 5 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x25 + ao_length as u64,
            extension: "axx".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &AXX_HEADER, Arc::new(AxxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axx_header_match() {
        let sig = AxxSignature;
        let mut buf = vec![0u8; 64];
        buf[..AXX_HEADER.len()].copy_from_slice(&AXX_HEADER);
        // aoLength at offset 0x25 = 10 (>= 5)
        buf[0x25..0x29].copy_from_slice(&10u32.to_le_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.min_filesize, 0x25 + 10);
    }

    #[test]
    fn test_axx_no_match() {
        let sig = AxxSignature;
        let mut buf = vec![0u8; 64];
        buf[..AXX_HEADER.len()].copy_from_slice(&AXX_HEADER);
        buf[0] = 0x00; // corrupt the GUID
        buf[0x25..0x29].copy_from_slice(&10u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // valid magic but aoLength < 5 also rejects
        let mut buf2 = vec![0u8; 64];
        buf2[..AXX_HEADER.len()].copy_from_slice(&AXX_HEADER);
        buf2[0x25..0x29].copy_from_slice(&3u32.to_le_bytes());
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
