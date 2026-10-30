use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Raw Fujifilm picture (RAF) carving signature. Header: "FUJIFILMCCD-RAW " (16 bytes) at offset 0.
/// Size is derived from the
/// JPEG/CFA offset+size fields in the 108-byte header (all big-endian); no footer.
struct RafSignature;

const HEADER_LEN: u64 = 108; // sizeof(struct header_raf)

impl FileSignature for RafSignature {
    fn name(&self) -> &str {
        "RAF"
    }
    fn extensions(&self) -> &[&str] {
        &["raf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 108 {
            return None;
        }
        let be32 =
            |o: usize| u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]) as u64;
        let jpg_offset = be32(84);
        let jpg_size = be32(88);
        let cfa_header_offset = be32(92);
        let cfa_header_size = be32(96);
        let cfa_offset = be32(100);
        let cfa_size = be32(104);

        let mut size: u64 = 0;
        if jpg_size > 0 {
            if jpg_offset < HEADER_LEN {
                return None;
            }
            let tmp = jpg_offset + jpg_size;
            if tmp > size {
                size = tmp;
            }
        }
        if cfa_size > 0 {
            if cfa_offset < HEADER_LEN {
                return None;
            }
            let tmp = cfa_offset + cfa_size;
            if size < tmp {
                size = tmp;
            }
        }
        if cfa_header_size > 0 {
            if cfa_header_offset < HEADER_LEN {
                return None;
            }
            let tmp = cfa_header_offset + cfa_header_size;
            if size < tmp {
                size = tmp;
            }
        }
        if size < HEADER_LEN {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: HEADER_LEN,
            extension: "raf".to_string(),
            calculated_file_size: Some(size),
        })
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
    registry.register(0, b"FUJIFILMCCD-RAW ", Arc::new(RafSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_header() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FUJIFILMCCD-RAW ");
        buf.resize(108, 0);
        buf
    }

    #[test]
    fn test_raf_header_match() {
        let sig = RafSignature;
        let mut buf = base_header();
        // jpg_offset=108 @84, jpg_size=200 @88
        buf[84..88].copy_from_slice(&108u32.to_be_bytes());
        buf[88..92].copy_from_slice(&200u32.to_be_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(308));
    }

    #[test]
    fn test_raf_no_match() {
        let sig = RafSignature;
        // wrong magic
        let mut bad = base_header();
        bad[0] = b'X';
        assert!(sig.header_check(&bad, 0).is_none());
        // jpg_offset inside header -> reject
        let mut buf = base_header();
        buf[84..88].copy_from_slice(&10u32.to_be_bytes());
        buf[88..92].copy_from_slice(&200u32.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // all sizes zero -> size < header -> reject
        assert!(sig.header_check(&base_header(), 0).is_none());
    }
}
