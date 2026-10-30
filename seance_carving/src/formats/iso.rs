use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ISO 9660 disk image carving signature. Header: primary volume descriptor magic
/// {0x01,'C','D','0','0','1'} at
/// offset 0x8000. When the both-endian volume_space_size and
/// logical_block_size fields agree, the size is
/// volume_space_size * logical_block_size. No footer.
/// The header lives at 0x8000, past the engine's 512-byte block, so the signature
/// asks for a header window (`header_window`) and the engine reads ahead for it.
struct IsoSignature;

/// Offset of the primary volume descriptor.
const PVD: usize = 0x8000;

impl FileSignature for IsoSignature {
    fn name(&self) -> &str {
        "ISO"
    }

    fn extensions(&self) -> &[&str] {
        &["iso"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // PhotoRec requires buffer_size >= 0x8000 + 512.
        if buf.len() < PVD + 512 {
            return None;
        }
        // volume_space_size_le at PVD+80, _be at PVD+84 (u32).
        let vss_le = u32::from_le_bytes(buf[PVD + 80..PVD + 84].try_into().unwrap());
        let vss_be = u32::from_be_bytes(buf[PVD + 84..PVD + 88].try_into().unwrap());
        // logical_block_size_le at PVD+128, _be at PVD+130 (u16).
        let lbs_le = u16::from_le_bytes(buf[PVD + 128..PVD + 130].try_into().unwrap());
        let lbs_be = u16::from_be_bytes(buf[PVD + 130..PVD + 132].try_into().unwrap());
        if vss_le == vss_be && lbs_le == lbs_be {
            let size = vss_le as u64 * lbs_le as u64;
            if size >= (PVD as u64 + 512) {
                return Some(RecoveryInit {
                    min_filesize: PVD as u64 + 512,
                    extension: "iso".to_string(),
                    calculated_file_size: Some(size),
                });
            }
        }
        // Fallback: valid magic but size not determinable -> carve heuristically.
        Some(RecoveryInit {
            min_filesize: PVD as u64 + 512,
            extension: "iso".to_string(),
            calculated_file_size: None,
        })
    }

    fn header_window(&self) -> usize {
        PVD + 512
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
    registry.register(
        0x8000,
        &[0x01, b'C', b'D', b'0', b'0', b'1'],
        Arc::new(IsoSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso_header_match() {
        let sig = IsoSignature;
        let mut buf = vec![0u8; PVD + 512];
        buf[PVD..PVD + 6].copy_from_slice(&[0x01, b'C', b'D', b'0', b'0', b'1']);
        // both-endian volume_space_size = 100, logical_block_size = 2048.
        buf[PVD + 80..PVD + 84].copy_from_slice(&100u32.to_le_bytes());
        buf[PVD + 84..PVD + 88].copy_from_slice(&100u32.to_be_bytes());
        buf[PVD + 128..PVD + 130].copy_from_slice(&2048u16.to_le_bytes());
        buf[PVD + 130..PVD + 132].copy_from_slice(&2048u16.to_be_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(100 * 2048));
    }

    #[test]
    fn test_iso_no_match() {
        let sig = IsoSignature;
        // Buffer too small to reach the primary volume descriptor.
        assert!(sig.header_check(&[0u8; 16], 0).is_none());
    }
}
