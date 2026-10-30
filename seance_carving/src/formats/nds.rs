use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Nintendo DS Game ROM Image (NDS) carving signature. Ported from file_nds.c.
/// Header: Nintendo logo CRC {0x24,0xff,0xae,0x51,0x69,0x9a} at offset 0xc0.
/// Rejected when bytes 0x0c..0x10 equal "NTRJ".
struct NdsSignature;

const NDS_MAGIC: &[u8] = &[0x24, 0xff, 0xae, 0x51, 0x69, 0x9a];

impl FileSignature for NdsSignature {
    fn name(&self) -> &str {
        "NDS"
    }

    fn extensions(&self) -> &[&str] {
        &["nds"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0xc6 && &buf[0xc0..0xc6] == NDS_MAGIC && &buf[0x0c..0x10] != b"NTRJ" {
            Some(RecoveryInit {
                min_filesize: 0x180,
                extension: "nds".to_string(),
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
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0xc0, NDS_MAGIC, Arc::new(NdsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nds_header_match() {
        let sig = NdsSignature;
        let mut buf = vec![0u8; 0xc6];
        buf[0xc0..0xc6].copy_from_slice(NDS_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_nds_no_match() {
        let sig = NdsSignature;
        // Magic present but NTRJ marker at 0x0c rejects it.
        let mut buf = vec![0u8; 0xc6];
        buf[0xc0..0xc6].copy_from_slice(NDS_MAGIC);
        buf[0x0c..0x10].copy_from_slice(b"NTRJ");
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let bad = vec![0u8; 0xc6];
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
