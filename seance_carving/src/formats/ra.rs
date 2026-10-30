use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Real Audio carving signature. Header: ".ra\xfd" at offset 0. Version byte at offset 4/5 selects
/// V3 (0x0003)
/// or V4 (0x0004 with ".ra4" at offset 8). Exact size is computed from the
/// big-endian header_size + data_size fields; no footer.
struct RaSignature;

impl FileSignature for RaSignature {
    fn name(&self) -> &str {
        "RealAudio"
    }
    fn extensions(&self) -> &[&str] {
        &["ra"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 6 {
            return None;
        }
        // V3: buffer[4]==0x00 && buffer[5]==0x03
        if buf[4] == 0x00 && buf[5] == 0x03 {
            if buf.len() < 22 {
                return None;
            }
            let header_size = u16::from_be_bytes([buf[6], buf[7]]) as u64;
            let data_size = u32::from_be_bytes([buf[18], buf[19], buf[20], buf[21]]) as u64;
            let calc = 8 + header_size + data_size;
            return Some(RecoveryInit {
                min_filesize: 8,
                extension: "ra".to_string(),
                calculated_file_size: Some(calc),
            });
        }
        // V4: buffer[4]==0x00 && buffer[5]==0x04 && ".ra4" at offset 8
        if buf[4] == 0x00 && buf[5] == 0x04 {
            if buf.len() < 20 {
                return None;
            }
            if &buf[8..12] != b".ra4" {
                return None;
            }
            let data_size = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]) as u64;
            let header_size = u16::from_be_bytes([buf[18], buf[19]]) as u64;
            let calc = 40 + header_size + data_size;
            return Some(RecoveryInit {
                min_filesize: 40,
                extension: "ra".to_string(),
                calculated_file_size: Some(calc),
            });
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[b'.', b'r', b'a', 0xfd], Arc::new(RaSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ra_header_match() {
        let sig = RaSignature;
        // V3: ".ra\xfd", version 0x0003, header_size=0x0010 @6, data_size=0x100 @18
        let mut buf = vec![b'.', b'r', b'a', 0xfd, 0x00, 0x03];
        buf.extend_from_slice(&[0x00, 0x10]); // header_size @6
        buf.extend_from_slice(&[0u8; 10]); // unk1 @8..18
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // data_size @18
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(8 + 0x10 + 0x100));
    }

    #[test]
    fn test_ra_v4_header_match() {
        let sig = RaSignature;
        // V4: version 0x0004, ".ra4" @8, data_size @12, header_size @18
        let mut buf = vec![b'.', b'r', b'a', 0xfd, 0x00, 0x04, 0x00, 0x00];
        buf.extend_from_slice(b".ra4"); // @8..12
        buf.extend_from_slice(&[0x00, 0x00, 0x02, 0x00]); // data_size @12
        buf.extend_from_slice(&[0x00, 0x00]); // version2 @16
        buf.extend_from_slice(&[0x00, 0x20]); // header_size @18
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(40 + 0x20 + 0x200));
    }

    #[test]
    fn test_ra_no_match() {
        let sig = RaSignature;
        // wrong version byte
        let buf = vec![b'.', b'r', b'a', 0xfd, 0x00, 0x09, 0x00, 0x00];
        assert!(sig.header_check(&buf, 0).is_none());
        // too short
        assert!(sig.header_check(b".ra", 0).is_none());
    }
}
