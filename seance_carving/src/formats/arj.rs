use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ARJ archive carving signature. Header: {0x60,0xEA} at offset 0, followed by main-header field
/// validation.
/// Secured archives (flag 0x40) encode their size; other archives use the
/// {0x60,0xEA,0x00,0x00} end-of-archive footer.
struct ArjSignature;

const ARJ_MAGIC: &[u8] = &[0x60, 0xEA];
const ARJ_FOOTER: &[u8] = &[0x60, 0xEA, 0x00, 0x00];

fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl FileSignature for ArjSignature {
    fn name(&self) -> &str {
        "ARJ"
    }

    fn extensions(&self) -> &[&str] {
        &["arj"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 24 || buf[0] != 0x60 || buf[1] != 0xEA {
            return None;
        }
        let basic_header_size = le16(buf, 2);
        let archiver_ver = buf[5];
        let archiver_ver_min = buf[6];
        let flags = buf[8];
        let file_type = buf[10];
        if basic_header_size == 0
            || basic_header_size > 2600
            || archiver_ver_min > archiver_ver
            || archiver_ver > 12
            || flags & 0x01 != 0
            || file_type != 2
        {
            return None;
        }
        let calculated_file_size = if flags & 0x40 != 0 {
            // Secured archive: size field is authoritative.
            let size = le32(buf, 20) as u64;
            if size < 34 {
                return None;
            }
            Some(size)
        } else {
            None
        };
        Some(RecoveryInit {
            min_filesize: 34,
            extension: "arj".to_string(),
            calculated_file_size,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Secured archives stop by calculated size; others scan for the footer.
        if recovery.calculated_file_size.is_some() {
            return DataCheckResult::Continue;
        }
        match footer_end_spanning(buf, recovery, ARJ_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, ARJ_MAGIC, Arc::new(ArjSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arj_header_match() {
        let mut buf = vec![0u8; 24];
        buf[0] = 0x60;
        buf[1] = 0xEA;
        buf[2..4].copy_from_slice(&100u16.to_le_bytes()); // basic_header_size
        buf[5] = 5; // archiver_ver
        buf[6] = 3; // archiver_ver_min <= ver
        buf[8] = 0x00; // flags (not secured, bit0 clear)
        buf[10] = 2; // file_type
        let init = ArjSignature.header_check(&buf, 0).unwrap();
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_arj_no_match() {
        // Wrong magic.
        assert!(ArjSignature.header_check(&[0u8; 24], 0).is_none());
        // Correct magic but file_type != 2.
        let mut buf = vec![0u8; 24];
        buf[0] = 0x60;
        buf[1] = 0xEA;
        buf[2..4].copy_from_slice(&100u16.to_le_bytes());
        buf[5] = 5;
        buf[6] = 3;
        buf[10] = 9;
        assert!(ArjSignature.header_check(&buf, 0).is_none());
    }
}
