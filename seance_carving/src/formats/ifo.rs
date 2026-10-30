use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DVD Video IFO carving signature. Header: "DVDVIDEO-VMG" or "DVDVIDEO-VTS" (12 bytes) at offset
/// 0.
/// Size from header: calculated_file_size = (be32(ls_IFO)+1)*2048 where the
/// big-endian ls_IFO sector count lives at offset 28. No footer.
struct IfoSignature;

impl FileSignature for IfoSignature {
    fn name(&self) -> &str {
        "IFO"
    }

    fn extensions(&self) -> &[&str] {
        &["ifo"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 32 && (&buf[0..12] == b"DVDVIDEO-VMG" || &buf[0..12] == b"DVDVIDEO-VTS") {
            let ls_ifo = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
            let size = (ls_ifo as u64 + 1) * 2048;
            Some(RecoveryInit {
                min_filesize: 2048,
                extension: "ifo".to_string(),
                calculated_file_size: Some(size),
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
    registry.register(0, b"DVDVIDEO-VMG", Arc::new(IfoSignature));
    registry.register(0, b"DVDVIDEO-VTS", Arc::new(IfoSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ifo_header_match() {
        let sig = IfoSignature;
        let mut buf = vec![0u8; 32];
        buf[0..12].copy_from_slice(b"DVDVIDEO-VMG");
        // ls_IFO = 1 (big-endian) at offset 28 -> size = (1+1)*2048
        buf[28..32].copy_from_slice(&1u32.to_be_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(2 * 2048));

        let mut buf2 = vec![0u8; 32];
        buf2[0..12].copy_from_slice(b"DVDVIDEO-VTS");
        assert!(sig.header_check(&buf2, 0).is_some());
    }

    #[test]
    fn test_ifo_no_match() {
        let sig = IfoSignature;
        let mut buf = vec![0u8; 32];
        buf[0..12].copy_from_slice(b"NOTADVDVIDEO");
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
