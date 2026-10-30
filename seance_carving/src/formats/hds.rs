use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Parallels disk image (HDS) carving signature. Header: magic "WithoutFreeSpace" + version
/// 0x00000002 (LE) at offset 0. The
/// geometry fields heads/cylinders/tracks/nb_sectors (LE uint32) must all be
/// non-zero. No footer; size bounded by max_file_size.
struct HdsSignature;

const HDS_MAGIC: &[u8] = b"WithoutFreeSpace\x02\x00\x00\x00";

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

impl FileSignature for HdsSignature {
    fn name(&self) -> &str {
        "Parallels HDS"
    }
    fn extensions(&self) -> &[&str] {
        &["hds"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 40 || &buf[0..20] != HDS_MAGIC {
            return None;
        }
        // heads(20), cylinders(24), tracks(28), nb_sectors(36) must be non-zero
        if le32(buf, 20) == 0 || le32(buf, 24) == 0 || le32(buf, 28) == 0 || le32(buf, 36) == 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 64,
            extension: "hds".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, HDS_MAGIC, Arc::new(HdsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..20].copy_from_slice(HDS_MAGIC);
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // heads
        buf[24..28].copy_from_slice(&1u32.to_le_bytes()); // cylinders
        buf[28..32].copy_from_slice(&1u32.to_le_bytes()); // tracks
        buf[36..40].copy_from_slice(&1u32.to_le_bytes()); // nb_sectors
        buf
    }

    #[test]
    fn test_hds_header_match() {
        let sig = HdsSignature;
        assert!(sig.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_hds_no_match() {
        let sig = HdsSignature;
        // zero heads
        let mut buf = valid_header();
        buf[20..24].copy_from_slice(&0u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // wrong magic
        let mut buf2 = valid_header();
        buf2[0] = b'X';
        assert!(sig.header_check(&buf2, 0).is_none());
        // too short
        assert!(sig.header_check(b"WithoutFreeSpace", 0).is_none());
    }
}
