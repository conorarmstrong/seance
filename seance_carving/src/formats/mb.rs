use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Maya carving signature. Header: "FOR4" at offset 0, big-endian u32 size at 4, then
/// "MayaFOR4"/"MAYAFOR4"/"MPLEFOR4" at offset 8.
/// Maya (.mb) encodes size (be32 + 8); Maya preview (.mp) is header-only.
struct MbSignature;

impl FileSignature for MbSignature {
    fn name(&self) -> &str {
        "Maya"
    }
    fn extensions(&self) -> &[&str] {
        &["mb", "mp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct maya_header: magic[4] "FOR4" + size(be32) + magic2[8] = 16 bytes.
        if buf.len() < 16 || &buf[0..4] != b"FOR4" {
            return None;
        }
        let tag = &buf[8..16];
        if tag == b"MayaFOR4" || tag == b"MAYAFOR4" {
            let size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            if size < 8 {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "mb".to_string(),
                calculated_file_size: Some(size as u64 + 8),
            })
        } else if tag == b"MPLEFOR4" {
            Some(RecoveryInit {
                min_filesize: 16,
                extension: "mp".to_string(),
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
    registry.register(8, b"MayaFOR4", Arc::new(MbSignature));
    registry.register(8, b"MAYAFOR4", Arc::new(MbSignature));
    registry.register(8, b"MPLEFOR4", Arc::new(MbSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mb_header_match() {
        let sig = MbSignature;
        let mut buf = b"FOR4".to_vec();
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(b"MayaFOR4");
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "mb");
        assert_eq!(init.calculated_file_size, Some(108));
    }

    #[test]
    fn test_mb_mp_variant() {
        let sig = MbSignature;
        let mut buf = b"FOR4".to_vec();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(b"MPLEFOR4");
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.extension, "mp");
        assert_eq!(init.calculated_file_size, None);
    }

    #[test]
    fn test_mb_no_match() {
        let sig = MbSignature;
        let mut buf = b"FOR4".to_vec();
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(b"NOPEFOR4");
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"FOR4", 0).is_none());
    }
}
