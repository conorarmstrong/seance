use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Cineon/SMPTE DPX image carving signature. Header: magic "SDPX" (big-endian) or "XPDS"
/// (little-endian) at offset 0,
/// version string "V1.0\0\0\0\0" at offset 8, and the file size (u32) at
/// offset 16. Size comes straight from the header. The size is in the file's
/// own byte order (SMPTE 268M): big-endian after "SDPX", little-endian after
/// "XPDS". PhotoRec reads it big-endian for both; that misreads every
/// little-endian file, so it is not ported.
struct DpxSignature;

const DPX_HEADER_SIZE: u32 = 768; // sizeof(struct header_dpx), packed

impl FileSignature for DpxSignature {
    fn name(&self) -> &str {
        "DPX"
    }

    fn extensions(&self) -> &[&str] {
        &["dpx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 20 {
            return None;
        }
        // vers[8] at offset 8 must equal "V1.0\0\0\0\0".
        if &buf[8..16] != b"V1.0\x00\x00\x00\x00" {
            return None;
        }
        let size_bytes = [buf[16], buf[17], buf[18], buf[19]];
        let file_size = if buf[..4] == *b"XPDS" {
            u32::from_le_bytes(size_bytes)
        } else {
            u32::from_be_bytes(size_bytes)
        };
        if file_size < DPX_HEADER_SIZE {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: DPX_HEADER_SIZE as u64,
            extension: "dpx".to_string(),
            calculated_file_size: Some(file_size as u64),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        10 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"SDPX", Arc::new(DpxSignature));
    registry.register(0, b"XPDS", Arc::new(DpxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(file_size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(b"SDPX");
        buf[8..16].copy_from_slice(b"V1.0\x00\x00\x00\x00");
        buf[16..20].copy_from_slice(&file_size.to_be_bytes());
        buf
    }

    #[test]
    fn test_dpx_header_match() {
        let sig = DpxSignature;
        let buf = make_header(4096);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(4096));
    }

    /// A little-endian ("XPDS") file stores its size little-endian too.
    #[test]
    fn test_dpx_little_endian_size_is_read_little_endian() {
        let mut buf = make_header(0);
        buf[0..4].copy_from_slice(b"XPDS");
        buf[16..20].copy_from_slice(&0x00C0_0000u32.to_le_bytes());
        let init = DpxSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x00C0_0000));
        // Under the header size in its own byte order: refused.
        buf[16..20].copy_from_slice(&100u32.to_le_bytes());
        assert!(DpxSignature.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_dpx_no_match() {
        let sig = DpxSignature;
        // Wrong version string.
        let mut buf = make_header(4096);
        buf[8..16].copy_from_slice(b"V2.0\x00\x00\x00\x00");
        assert!(sig.header_check(&buf, 0).is_none());
        // File size smaller than header.
        assert!(sig.header_check(&make_header(100), 0).is_none());
    }
}
