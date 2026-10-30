use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// HFS+/HFSX volume header signature. Header: "H+\0\4" (HFS+) or "HX\0\5" (HFSX) at offset 0. The
/// hfsp_vh volume
/// header is validated: blocksize (offset 0x28) is a non-zero multiple of 512
/// and free_blocks (0x30) <= total_blocks (0x2C), all big-endian.
struct HfspSignature;

const HFSP_MAGIC: &[u8] = &[b'H', b'+', 0x00, 0x04];
const HFSX_MAGIC: &[u8] = &[b'H', b'X', 0x00, 0x05];

impl FileSignature for HfspSignature {
    fn name(&self) -> &str {
        "HFSP"
    }
    fn extensions(&self) -> &[&str] {
        &["hfsp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 52 {
            return None;
        }
        if &buf[0..4] != HFSP_MAGIC && &buf[0..4] != HFSX_MAGIC {
            return None;
        }
        let blocksize = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let total_blocks = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]);
        let free_blocks = u32::from_be_bytes([buf[48], buf[49], buf[50], buf[51]]);
        if blocksize != 0 && blocksize.is_multiple_of(512) && free_blocks <= total_blocks {
            Some(RecoveryInit {
                min_filesize: 512,
                extension: "hfsp".to_string(),
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
        2048
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, HFSP_MAGIC, Arc::new(HfspSignature));
    registry.register(0, HFSX_MAGIC, Arc::new(HfspSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_vh() -> Vec<u8> {
        let mut buf = vec![0u8; 52];
        buf[0..4].copy_from_slice(HFSP_MAGIC);
        // blocksize = 512 at offset 0x28 (big-endian)
        buf[40..44].copy_from_slice(&512u32.to_be_bytes());
        // total_blocks = 10 at offset 0x2C
        buf[44..48].copy_from_slice(&10u32.to_be_bytes());
        // free_blocks = 5 at offset 0x30
        buf[48..52].copy_from_slice(&5u32.to_be_bytes());
        buf
    }

    #[test]
    fn test_hfsp_header_match() {
        let sig = HfspSignature;
        assert!(sig.header_check(&valid_vh(), 0).is_some());
    }

    #[test]
    fn test_hfsp_no_match() {
        let sig = HfspSignature;
        // Valid magic but blocksize not a multiple of 512.
        let mut buf = valid_vh();
        buf[40..44].copy_from_slice(&500u32.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(&[0u8; 52], 0).is_none());
    }
}
