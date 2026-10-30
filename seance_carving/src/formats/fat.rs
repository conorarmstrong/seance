use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FAT filesystem image carving signature. Header: boot sector marker 0x55 0xAA at offset 0x1fe,
/// plus a jump
/// instruction, sane sectors-per-cluster, bytes-per-sector and media byte.
/// No footer; carves until the next header or max size.
struct FatSignature;

const FAT_MARKER: &[u8] = &[0x55, 0xAA];

impl FileSignature for FatSignature {
    fn name(&self) -> &str {
        "FAT"
    }
    fn extensions(&self) -> &[&str] {
        &["fat"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 512 {
            return None;
        }
        // Boot sector signature (le16 marker == 0xAA55) at 0x1fe.
        if buf[0x1fe] != 0x55 || buf[0x1ff] != 0xAA {
            return None;
        }
        // Jump instruction (ignored[0..3]).
        let jmp0 = buf[0];
        if jmp0 != 0xeb && jmp0 != 0xe9 {
            return None;
        }
        if jmp0 == 0xeb && buf[2] != 0x90 {
            return None;
        }
        // Number of FATs (offset 0x10).
        if buf[0x10] != 1 && buf[0x10] != 2 {
            return None;
        }
        // Sectors per cluster (offset 0x0d): power of two, 1..=128.
        match buf[0x0d] {
            1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 => {}
            _ => return None,
        }
        // Bytes per sector (le16 at 0x0b): non-zero multiple of 512.
        let sector_size = u16::from_le_bytes([buf[0x0b], buf[0x0c]]) as u32;
        if sector_size == 0 || !sector_size.is_multiple_of(512) {
            return None;
        }
        // Media descriptor (offset 0x15): 0xF0 or >= 0xF8.
        let media = buf[0x15];
        if media != 0xF0 && media < 0xF8 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 512,
            extension: "fat".to_string(),
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
    registry.register(0x1fe, FAT_MARKER, Arc::new(FatSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_boot_sector() -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0] = 0xeb;
        buf[2] = 0x90;
        buf[0x0b] = 0x00; // bytes/sector = 512 (le16)
        buf[0x0c] = 0x02;
        buf[0x0d] = 1; // sectors/cluster
        buf[0x10] = 2; // number of FATs
        buf[0x15] = 0xF8; // media
        buf[0x1fe] = 0x55;
        buf[0x1ff] = 0xAA;
        buf
    }

    #[test]
    fn test_fat_header_match() {
        let sig = FatSignature;
        assert!(sig.header_check(&valid_boot_sector(), 0).is_some());
    }

    #[test]
    fn test_fat_no_match() {
        let sig = FatSignature;
        // All zeros: missing boot marker.
        assert!(sig.header_check(&vec![0u8; 512], 0).is_none());
        // Correct marker but bad jump byte.
        let mut buf = valid_boot_sector();
        buf[0] = 0x00;
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
