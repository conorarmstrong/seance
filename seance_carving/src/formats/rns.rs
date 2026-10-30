use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Reason Audio File carving signature. Header at offset 0: ASCII "Propellerheads Reason Song
/// File". No footer/size.
struct RnsSignature;

const RNS_MAGIC: &[u8] = b"Propellerheads Reason Song File";

impl FileSignature for RnsSignature {
    fn name(&self) -> &str {
        "RNS"
    }
    fn extensions(&self) -> &[&str] {
        &["rns"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= RNS_MAGIC.len() && &buf[0..RNS_MAGIC.len()] == RNS_MAGIC {
            Some(RecoveryInit {
                min_filesize: RNS_MAGIC.len() as u64,
                extension: "rns".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, RNS_MAGIC, Arc::new(RnsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rns_header_match() {
        let sig = RnsSignature;
        let mut buf = RNS_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 16]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_rns_no_match() {
        let sig = RnsSignature;
        assert!(sig
            .header_check(b"Propellerheads Reason NOT a song", 0)
            .is_none());
        assert!(sig.header_check(b"Prop", 0).is_none());
    }
}
