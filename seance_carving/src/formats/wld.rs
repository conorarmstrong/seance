use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WLD (Terraria world) carving signature. Ported from file_wld.c.
/// Header: 00 00 00 "relogic" (10 bytes) at offset 1. The file-type byte at 0x0B
/// selects the extension: 1 -> map, 2 -> wld (world), 3 -> plr (player).
struct WldSignature;

const WLD_MAGIC: &[u8] = &[0x00, 0x00, 0x00, b'r', b'e', b'l', b'o', b'g', b'i', b'c'];

impl FileSignature for WldSignature {
    fn name(&self) -> &str {
        "WLD"
    }
    fn extensions(&self) -> &[&str] {
        &["wld", "map", "plr"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Magic sits at offset 1; the type byte is at 0x0B.
        if buf.len() < 0x0c {
            return None;
        }
        if &buf[1..11] != WLD_MAGIC {
            return None;
        }
        let extension = match buf[0x0b] {
            0x01 => "map",
            0x02 => "wld",
            0x03 => "plr",
            _ => return None,
        };
        Some(RecoveryInit {
            min_filesize: 0x0c,
            extension: extension.to_string(),
            calculated_file_size: None,
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
    registry.register(1, WLD_MAGIC, Arc::new(WldSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_with_type(t: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 0x0c];
        buf[1..11].copy_from_slice(WLD_MAGIC);
        buf[0x0b] = t;
        buf
    }

    #[test]
    fn test_wld_header_match() {
        let sig = WldSignature;
        assert_eq!(
            sig.header_check(&header_with_type(2), 0).unwrap().extension,
            "wld"
        );
        assert_eq!(
            sig.header_check(&header_with_type(1), 0).unwrap().extension,
            "map"
        );
        assert_eq!(
            sig.header_check(&header_with_type(3), 0).unwrap().extension,
            "plr"
        );
    }

    #[test]
    fn test_wld_no_match() {
        let sig = WldSignature;
        assert!(sig.header_check(&header_with_type(5), 0).is_none()); // bad type byte
        let mut bad = header_with_type(2);
        bad[4] = b'X'; // corrupt magic
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
