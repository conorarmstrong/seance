use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// InstallShield header carving signature. Header: magic "ISc(" at offset 0. The header struct
/// requires the LE uint16 at
/// offset 6 to be 0x100 and the LE uint32 at offset 8 to be 0. When the "cab"
/// marker fields are present (unk2==0 and filesize==0x200) the file is a "cab";
/// otherwise the LE uint32 filesize at offset 20 gives the total size.
struct HdrSignature;

const HDR_MAGIC: &[u8] = b"ISc(";

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

impl FileSignature for HdrSignature {
    fn name(&self) -> &str {
        "InstallShield"
    }
    fn extensions(&self) -> &[&str] {
        &["hdr", "cab"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 28 || &buf[0..4] != HDR_MAGIC {
            return None;
        }
        if le16(buf, 6) != 0x100 {
            return None;
        }
        if le32(buf, 8) != 0 {
            return None;
        }
        let filesize = le32(buf, 20);
        if le16(buf, 16) == 0 && filesize == 0x200 {
            return Some(RecoveryInit {
                min_filesize: 0x200,
                extension: "cab".to_string(),
                calculated_file_size: None,
            });
        }
        Some(RecoveryInit {
            min_filesize: 28,
            extension: "hdr".to_string(),
            calculated_file_size: Some(filesize as u64),
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
    registry.register(0, HDR_MAGIC, Arc::new(HdrSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_header() -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(b"ISc(");
        // val0100 at offset 6 = 0x0100 little-endian
        buf[6] = 0x00;
        buf[7] = 0x01;
        // val00000000 at offset 8 stays 0
        buf
    }

    #[test]
    fn test_hdr_header_match() {
        let sig = HdrSignature;
        let mut buf = base_header();
        // filesize (offset 20) = 0x4000, unk2 (offset 16) non-zero -> hdr branch
        buf[16] = 0x05;
        buf[20..24].copy_from_slice(&0x4000u32.to_le_bytes());
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "hdr");
        assert_eq!(init.calculated_file_size, Some(0x4000));
    }

    #[test]
    fn test_hdr_cab_branch() {
        let sig = HdrSignature;
        let mut buf = base_header();
        // unk2 (offset 16) == 0 and filesize (offset 20) == 0x200 -> cab
        buf[20..24].copy_from_slice(&0x200u32.to_le_bytes());
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "cab");
    }

    #[test]
    fn test_hdr_no_match() {
        let sig = HdrSignature;
        // wrong magic
        let mut buf = base_header();
        buf[0] = b'X';
        assert!(sig.header_check(&buf, 0).is_none());
        // wrong val0100
        let mut buf2 = base_header();
        buf2[6] = 0xff;
        assert!(sig.header_check(&buf2, 0).is_none());
        // too short
        assert!(sig.header_check(b"ISc(", 0).is_none());
    }
}
