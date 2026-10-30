use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Material Exchange Format (MXF) carving signature. Header: SMPTE KLV key
/// {0x06,0x0e,0x2b,0x34,0x02,0x05,0x01,0x01,0x0d,0x01,0x02} at
/// offset 0, with byte 0x0d == 0x02 and byte 0x0e == 0x04.
/// PhotoRec walks the KLV packet chain (data_check_mxf) and derives the size from the
/// footer_partition field; that stateful traversal is not implemented (degraded to header
/// magic + max size).
struct MxfSignature;

const MXF_MAGIC: &[u8] = &[
    0x06, 0x0e, 0x2b, 0x34, 0x02, 0x05, 0x01, 0x01, 0x0d, 0x01, 0x02,
];

impl FileSignature for MxfSignature {
    fn name(&self) -> &str {
        "MXF"
    }

    fn extensions(&self) -> &[&str] {
        &["mxf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 0x0f && &buf[0..11] == MXF_MAGIC && buf[0x0d] == 0x02 && buf[0x0e] == 0x04 {
            Some(RecoveryInit {
                min_filesize: 0x26,
                extension: "mxf".to_string(),
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
        2_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MXF_MAGIC, Arc::new(MxfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mxf_header_match() {
        let sig = MxfSignature;
        let mut buf = vec![0u8; 0x0f];
        buf[0..11].copy_from_slice(MXF_MAGIC);
        buf[0x0d] = 0x02;
        buf[0x0e] = 0x04;
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_mxf_no_match() {
        let sig = MxfSignature;
        // Right magic but wrong 0x0d/0x0e discriminator bytes.
        let mut buf = vec![0u8; 0x0f];
        buf[0..11].copy_from_slice(MXF_MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        let bad = vec![0u8; 0x0f];
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
