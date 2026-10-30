use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Gerber Graphix Advantage plot carving signature. Header: "Gerber Scientific Products GRAPHIX
/// ADVANTAGE" (44 bytes) at offset 2.
/// No footer, no size.
struct PltSignature;

const PLT_MAGIC: &[u8] = b"Gerber Scientific Products GRAPHIX ADVANTAGE";
const PLT_OFFSET: usize = 2;

impl FileSignature for PltSignature {
    fn name(&self) -> &str {
        "Gerber Graphix Advantage"
    }
    fn extensions(&self) -> &[&str] {
        &["plt"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let end = PLT_OFFSET + PLT_MAGIC.len();
        if buf.len() >= end && &buf[PLT_OFFSET..end] == PLT_MAGIC {
            Some(RecoveryInit {
                min_filesize: end as u64,
                extension: "plt".to_string(),
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
    registry.register(PLT_OFFSET as u16, PLT_MAGIC, Arc::new(PltSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plt_header_match() {
        let sig = PltSignature;
        let mut buf = vec![0u8, 0u8]; // 2-byte prefix before magic
        buf.extend_from_slice(PLT_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_plt_no_match() {
        let sig = PltSignature;
        // Magic present but at offset 0 (wrong offset) -> should not match.
        assert!(sig.header_check(PLT_MAGIC, 0).is_none());
        assert!(sig.header_check(b"\x00\x00Gerber X", 0).is_none());
    }
}
