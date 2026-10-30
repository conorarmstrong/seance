use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Dump/Restore archive carving signature. Magic: c_magic {0x6b,0xea,0x00,0x00} (old fs) or
/// {0x6c,0xea,0x00,0x00}
/// (new fs) at offset 0x18. header_check additionally requires the record type
/// c_type (little-endian, offset 0) to equal TS_TAPE (1).
struct DumpSignature;

const TS_TAPE: u32 = 1;

impl FileSignature for DumpSignature {
    fn name(&self) -> &str {
        "Dump"
    }

    fn extensions(&self) -> &[&str] {
        &["dump"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // buf begins at the file start; the magic sits at offset 0x18 and is
        // matched by the registry. Here we validate c_type == TS_TAPE.
        if buf.len() >= 4 && u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) == TS_TAPE {
            Some(RecoveryInit {
                min_filesize: 0,
                extension: "dump".to_string(),
                calculated_file_size: None,
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
        (1u64 << 33) - 1
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    // c_magic at offset 0x18: old fs and new fs variants.
    registry.register(0x18, &[0x6b, 0xea, 0x00, 0x00], Arc::new(DumpSignature));
    registry.register(0x18, &[0x6c, 0xea, 0x00, 0x00], Arc::new(DumpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_header_match() {
        let sig = DumpSignature;
        let mut buf = vec![0u8; 0x1c];
        buf[0..4].copy_from_slice(&TS_TAPE.to_le_bytes());
        buf[0x18..0x1c].copy_from_slice(&[0x6b, 0xea, 0x00, 0x00]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_dump_no_match() {
        let sig = DumpSignature;
        // c_type is not TS_TAPE.
        let mut buf = vec![0u8; 0x1c];
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
