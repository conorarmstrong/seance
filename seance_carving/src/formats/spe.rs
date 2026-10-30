use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WinSpec bitmap image (SPE) carving signature. Header: the `WinView_id` field `67 45 23 01` (LE
/// 0x01234567) at
/// offset 0xBB4 (2996). Validation also requires the trailer marker
/// `lastvalue == 0x5555` at offset 4098 and a non-negative `NumFrames` at
/// offset 1446. The exact file size is computed as
/// `xdim*ydim*NumFrames*(datatype<=1?4:2) + 4100`. No footer.
struct SpeSignature;

const SPE_MAGIC: [u8; 4] = [0x67, 0x45, 0x23, 0x01];

impl FileSignature for SpeSignature {
    fn name(&self) -> &str {
        "SPE"
    }
    fn extensions(&self) -> &[&str] {
        &["spe"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need the full 4100-byte header (last field is at 4098).
        if buf.len() < 4100 {
            return None;
        }
        // WinView_id at 0xBB4 == 0x01234567 (LE bytes 67 45 23 01).
        if buf[0xbb4..0xbb4 + 4] != SPE_MAGIC {
            return None;
        }
        // Trailer marker lastvalue at 4098 must be 0x5555.
        if u16::from_le_bytes([buf[4098], buf[4099]]) != 0x5555 {
            return None;
        }
        let num_frames = i32::from_le_bytes([buf[1446], buf[1447], buf[1448], buf[1449]]);
        if num_frames < 0 {
            return None;
        }
        let xdim = u16::from_le_bytes([buf[42], buf[43]]) as u64;
        let ydim = u16::from_le_bytes([buf[656], buf[657]]) as u64;
        let datatype = u16::from_le_bytes([buf[108], buf[109]]);

        let mut tmp = xdim * ydim * (num_frames as u64);
        if tmp & 0xc000_0000_0000_0000 != 0 {
            return None;
        }
        tmp *= if datatype <= 1 { 4 } else { 2 };
        if tmp & 0x8000_0000_0000_0000 != 0 {
            return None;
        }
        tmp += 4100;

        Some(RecoveryInit {
            min_filesize: 4100,
            extension: "spe".to_string(),
            calculated_file_size: Some(tmp),
        })
    }

    /// The magic lies past the engine's 512-byte block: ask to be shown that far.
    fn header_window(&self) -> usize {
        4100
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    // WinView_id located 0xBB4 bytes into the file.
    registry.register(0xbb4, &SPE_MAGIC, Arc::new(SpeSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> Vec<u8> {
        let mut buf = vec![0u8; 4100];
        buf[0xbb4..0xbb4 + 4].copy_from_slice(&SPE_MAGIC); // WinView_id
        buf[42..44].copy_from_slice(&4u16.to_le_bytes()); // xdim
        buf[656..658].copy_from_slice(&4u16.to_le_bytes()); // ydim
        buf[108..110].copy_from_slice(&2u16.to_le_bytes()); // datatype
        buf[1446..1450].copy_from_slice(&1i32.to_le_bytes()); // NumFrames
        buf[4098..4100].copy_from_slice(&0x5555u16.to_le_bytes()); // lastvalue
        buf
    }

    #[test]
    fn test_spe_header_match() {
        let sig = SpeSignature;
        let buf = valid_header();
        let init = sig.header_check(&buf, 0).expect("should match");
        // 4*4*1 * 2 + 4100 = 4132
        assert_eq!(init.calculated_file_size, Some(4132));
    }

    #[test]
    fn test_spe_no_match() {
        let sig = SpeSignature;
        // Missing trailer marker
        let mut buf = valid_header();
        buf[4098] = 0x00;
        buf[4099] = 0x00;
        assert!(sig.header_check(&buf, 0).is_none());
        // Buffer too short to hold the header
        assert!(sig.header_check(&[0u8; 512], 0).is_none());
    }
}
