use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Autodesk 3D Studio (.3ds) model carving signature. Header: main chunk id 0x4d4d ("MM") at offset
/// 0, chunk length marker 0x02 0x00
/// 0x0a 0x00 at offset 6, and sub-chunk id 0x3d3d at offset 0x10. The file size is
/// the main chunk's next_chunk field (le32 at offset 2).
struct F3dsSignature;

const F3DS_MAGIC: &[u8] = &[0x02, 0x00, 0x0a, 0x00];

impl FileSignature for F3dsSignature {
    fn name(&self) -> &str {
        "3DS"
    }

    fn extensions(&self) -> &[&str] {
        &["3ds"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x12 {
            return None;
        }
        // Main chunk id 0x4d4d and sub-chunk id 0x3d3d.
        if buf[0] != 0x4d || buf[1] != 0x4d || buf[0x10] != 0x3d || buf[0x11] != 0x3d {
            return None;
        }
        // next_chunk (le32 at offset 2) is the total file size.
        let fs = u32::from_le_bytes(buf[2..6].try_into().unwrap()) as u64;
        if fs <= 0x12 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x12,
            extension: "3ds".to_string(),
            calculated_file_size: Some(fs),
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
    registry.register(6, F3DS_MAGIC, Arc::new(F3dsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(fs: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x12];
        buf[0] = 0x4d;
        buf[1] = 0x4d;
        buf[2..6].copy_from_slice(&fs.to_le_bytes());
        buf[6..10].copy_from_slice(F3DS_MAGIC);
        buf[0x10] = 0x3d;
        buf[0x11] = 0x3d;
        buf
    }

    #[test]
    fn test_f3ds_header_match() {
        let sig = F3dsSignature;
        let buf = make_header(4096);
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(4096));
    }

    #[test]
    fn test_f3ds_no_match() {
        let sig = F3dsSignature;
        // Missing sub-chunk id 0x3d3d.
        let mut buf = make_header(4096);
        buf[0x10] = 0x00;
        assert!(sig.header_check(&buf, 0).is_none());
        // File size too small.
        let buf2 = make_header(0x10);
        assert!(sig.header_check(&buf2, 0).is_none());
        assert!(sig.header_check(b"MM", 0).is_none());
    }
}
