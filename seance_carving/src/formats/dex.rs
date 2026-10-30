use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Dalvik executable (DEX) carving signature. Header: "dex\n" at offset 0, followed by three ASCII
/// version digits and a
/// NUL byte (bytes 4..7 digits, byte 7 == 0x00). file_size is a little-endian
/// u32 at offset 32; header_size (le32 @36) must be >= 0x28 and < file_size.
/// No footer.
struct DexSignature;

impl FileSignature for DexSignature {
    fn name(&self) -> &str {
        "DEX"
    }
    fn extensions(&self) -> &[&str] {
        &["dex"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 40
            && &buf[0..4] == b"dex\n"
            && buf[4].is_ascii_digit()
            && buf[5].is_ascii_digit()
            && buf[6].is_ascii_digit()
            && buf[7] == 0x00
        {
            let file_size = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
            let header_size = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
            if header_size < 0x28 {
                return None;
            }
            if header_size >= file_size {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 0x28,
                extension: "dex".to_string(),
                calculated_file_size: Some(file_size as u64),
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
    registry.register(0, b"dex\n", Arc::new(DexSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(file_size: u32, header_size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        buf[0..4].copy_from_slice(b"dex\n");
        buf[4..7].copy_from_slice(b"035");
        buf[7] = 0x00;
        buf[32..36].copy_from_slice(&file_size.to_le_bytes());
        buf[36..40].copy_from_slice(&header_size.to_le_bytes());
        buf
    }

    #[test]
    fn test_dex_header_match() {
        let init = DexSignature.header_check(&header(4096, 0x70), 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(4096));
    }

    #[test]
    fn test_dex_no_match() {
        // Wrong magic.
        let mut bad = header(4096, 0x70);
        bad[0..4].copy_from_slice(b"DEX!");
        assert!(DexSignature.header_check(&bad, 0).is_none());
        // header_size >= file_size.
        assert!(DexSignature.header_check(&header(0x40, 0x50), 0).is_none());
        // header_size below 0x28.
        assert!(DexSignature.header_check(&header(4096, 0x10), 0).is_none());
    }
}
