use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Java Keystore (JKS) carving signature. Header: magic {0xfe,0xed,0xfe,0xed,0x00,0x00,0x00,0x02}
/// at offset 0 (magic
/// 0xfeedfeed + version 2). The big-endian nbr_of_entries field at offset 8
/// must be non-zero. No footer; recovery runs until the next header or cap.
struct JksSignature;

/// jks_header magic + version (8 bytes) at offset 0.
const JKS_MAGIC: [u8; 8] = [0xfe, 0xed, 0xfe, 0xed, 0x00, 0x00, 0x00, 0x02];

impl FileSignature for JksSignature {
    fn name(&self) -> &str {
        "JKS"
    }

    fn extensions(&self) -> &[&str] {
        &["jks"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && buf[0..8] == JKS_MAGIC {
            let nbr_of_entries = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
            if nbr_of_entries == 0 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 12 + 4 + 2 + 8, // sizeof(jks_header)+4+2+8
                extension: "jks".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &JKS_MAGIC, Arc::new(JksSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jks_header_match() {
        let sig = JksSignature;
        let mut buf = JKS_MAGIC.to_vec();
        buf.extend_from_slice(&3u32.to_be_bytes()); // nbr_of_entries = 3
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_jks_no_match() {
        let sig = JksSignature;
        let mut buf = JKS_MAGIC.to_vec();
        buf.extend_from_slice(&0u32.to_be_bytes()); // nbr_of_entries = 0
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig
            .header_check(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 0)
            .is_none());
    }
}
