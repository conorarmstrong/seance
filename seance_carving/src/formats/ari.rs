use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ARRI Raw Video carving signature. Header: {"ARRI",0x12,0x34,0x56,0x78,0x00,0x10,0x00,0x00} at
/// offset 0, with
/// non-zero version/width/height fields. No footer.
struct AriSignature;

const ARI_MAGIC: &[u8] = &[
    b'A', b'R', b'R', b'I', 0x12, 0x34, 0x56, 0x78, 0x00, 0x10, 0x00, 0x00,
];

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl FileSignature for AriSignature {
    fn name(&self) -> &str {
        "ARI"
    }

    fn extensions(&self) -> &[&str] {
        &["ari"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct arri_header is 32 bytes: version@12, width@20, height@24.
        if buf.len() < 32 || &buf[0..12] != ARI_MAGIC {
            return None;
        }
        if le32(buf, 12) == 0 || le32(buf, 20) == 0 || le32(buf, 24) == 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 4096,
            extension: "ari".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, ARI_MAGIC, Arc::new(AriSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ari_header_match() {
        let mut buf = vec![0u8; 32];
        buf[0..12].copy_from_slice(ARI_MAGIC);
        buf[12..16].copy_from_slice(&3u32.to_le_bytes()); // version
        buf[20..24].copy_from_slice(&1920u32.to_le_bytes()); // width
        buf[24..28].copy_from_slice(&1080u32.to_le_bytes()); // height
        assert!(AriSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_ari_no_match() {
        // Correct magic but zero dimensions.
        let mut buf = vec![0u8; 32];
        buf[0..12].copy_from_slice(ARI_MAGIC);
        buf[12..16].copy_from_slice(&3u32.to_le_bytes());
        assert!(AriSignature.header_check(&buf, 0).is_none());
        // Wrong magic.
        assert!(AriSignature.header_check(&[0u8; 32], 0).is_none());
    }
}
