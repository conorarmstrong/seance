use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WavPack (Hybrid Lossless Wavefile Compressor) carving signature.
/// Header: "wvpk" (0x77 0x76 0x70 0x6B) at offset 0.
/// Note: PhotoRec's data_check_wv walks WavPack blocks plus trailing APE/ID3 tags to
/// compute the exact size. That stateful scan is not implemented; this uses min_filesize
/// = ckSize + 8 and lets the engine carve to the next header (degraded but correct).
struct WvSignature;

impl FileSignature for WvSignature {
    fn name(&self) -> &str {
        "WavPack"
    }

    fn extensions(&self) -> &[&str] {
        &["wv"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // sizeof(WavpackHeader) == 32
        if buf.len() < 32 || &buf[0..4] != b"wvpk" {
            return None;
        }
        let ck_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        let block_index = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if block_index != 0 {
            return None;
        }
        if 32 > ck_size + 8 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: ck_size + 8,
            extension: "wv".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, b"wvpk", Arc::new(WvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wv_header_match() {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(b"wvpk");
        // ckSize = 24 -> ckSize + 8 = 32 >= sizeof(WavpackHeader)
        buf[4..8].copy_from_slice(&24u32.to_le_bytes());
        // block_index = 0 (already zeroed)
        let sig = WvSignature;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.min_filesize, 32);
    }

    #[test]
    fn test_wv_no_match() {
        let sig = WvSignature;
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(b"wvpx");
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"wvpk", 0).is_none());
    }
}
