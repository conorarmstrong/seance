use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PCB Wizard carving signature. Header: "Dsg\x00\x0ad\x0a\x00" (8 bytes) at offset 0. No footer.
/// min_filesize 8.
struct PcbSignature;

const PCB_MAGIC: &[u8] = &[b'D', b's', b'g', 0x00, 0x0a, b'd', 0x0a, 0x00];

impl FileSignature for PcbSignature {
    fn name(&self) -> &str {
        "PCB Wizard"
    }
    fn extensions(&self) -> &[&str] {
        &["pcb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 8 && &buf[0..8] == PCB_MAGIC {
            Some(RecoveryInit {
                min_filesize: 8,
                extension: "pcb".to_string(),
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
    registry.register(0, PCB_MAGIC, Arc::new(PcbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcb_header_match() {
        let sig = PcbSignature;
        assert!(sig
            .header_check(&[b'D', b's', b'g', 0x00, 0x0a, b'd', 0x0a, 0x00, 0x11], 0)
            .is_some());
    }

    #[test]
    fn test_pcb_no_match() {
        let sig = PcbSignature;
        assert!(sig
            .header_check(&[b'D', b's', b'g', 0x01, 0x0a, b'd', 0x0a, 0x00], 0)
            .is_none());
        assert!(sig.header_check(b"Dsg", 0).is_none());
    }
}
