use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MediBang Paint Pro (MDP) carving signature. Header: 8-byte magic "mdipack\0" at offset 0. The
/// header encodes the exact
/// file size: le32(val1) + le32(val2) + 20, where val1/val2 are the u32 words
/// at offsets 12 and 16. No footer.
struct MdpSignature;

const MDP_MAGIC: &[u8] = &[b'm', b'd', b'i', b'p', b'a', b'c', b'k', 0x00];

impl FileSignature for MdpSignature {
    fn name(&self) -> &str {
        "MDP"
    }
    fn extensions(&self) -> &[&str] {
        &["mdp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 20 && &buf[0..8] == MDP_MAGIC {
            let val1 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as u64;
            let val2 = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]) as u64;
            let size = val1 + val2 + 20;
            Some(RecoveryInit {
                min_filesize: 20,
                extension: "mdp".to_string(),
                calculated_file_size: Some(size),
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MDP_MAGIC, Arc::new(MdpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdp_header_match() {
        let sig = MdpSignature;
        let mut buf = vec![0u8; 20];
        buf[0..8].copy_from_slice(MDP_MAGIC);
        buf[12..16].copy_from_slice(&100u32.to_le_bytes());
        buf[16..20].copy_from_slice(&50u32.to_le_bytes());
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(100 + 50 + 20));
    }

    #[test]
    fn test_mdp_no_match() {
        let sig = MdpSignature;
        let mut buf = vec![0u8; 20];
        buf[0..8].copy_from_slice(b"mdipackX");
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"mdipack\x00", 0).is_none());
    }
}
