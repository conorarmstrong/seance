use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Windows Event Log (.evt) carving signature. Header (offset 0): first chunk size le32 == 0x30
/// followed by "LfLe", and the
/// second chunk at offset 0x30 must have size >= 8.
/// Degraded: PhotoRec's data_check chunk-walker (which sums record lengths to size
/// the file) is not implemented; recovery falls back to header magic + chunk validation.
struct EvtSignature;

const EVT_MAGIC: &[u8] = &[0x30, 0x00, 0x00, 0x00, 0x4c, 0x66, 0x4c, 0x65];

impl FileSignature for EvtSignature {
    fn name(&self) -> &str {
        "EVT"
    }

    fn extensions(&self) -> &[&str] {
        &["evt"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // First chunk: size == 0x30 and signature "LfLe" (covered by the magic).
        if buf.len() < EVT_MAGIC.len() || &buf[..EVT_MAGIC.len()] != EVT_MAGIC {
            return None;
        }
        // Second chunk lives at offset 0x30; its size field must be >= 8.
        if buf.len() < 0x34 {
            return None;
        }
        let chunk2_size = u32::from_le_bytes(buf[0x30..0x34].try_into().unwrap());
        if chunk2_size < 8 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 0x30,
            extension: "evt".to_string(),
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
    registry.register(0, EVT_MAGIC, Arc::new(EvtSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evt_header_match() {
        let sig = EvtSignature;
        let mut buf = vec![0u8; 0x34];
        buf[..8].copy_from_slice(EVT_MAGIC);
        // Second chunk size at 0x30 = 8.
        buf[0x30] = 0x08;
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_evt_no_match() {
        let sig = EvtSignature;
        // Wrong magic.
        let mut buf = vec![0u8; 0x34];
        buf[..8].copy_from_slice(&[0x30, 0x00, 0x00, 0x00, b'X', b'X', b'X', b'X']);
        assert!(sig.header_check(&buf, 0).is_none());
        // Correct magic but second chunk size < 8.
        let mut buf2 = vec![0u8; 0x34];
        buf2[..8].copy_from_slice(EVT_MAGIC);
        buf2[0x30] = 0x02;
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
